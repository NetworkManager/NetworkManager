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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#include <config.h>

#include <netinet/ether.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <gio/gio.h>
#include <glib/gi18n.h>

#include "nm-glib-compat.h"
#include "nm-manager.h"
#include "nm-logging.h"
#include "nm-dbus-manager.h"
#include "nm-vpn-manager.h"
#include "nm-modem-manager.h"
#include "nm-device-bt.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-device-olpc-mesh.h"
#if WITH_WIMAX
#include "nm-device-wimax.h"
#endif
#include "nm-device-modem.h"
#include "nm-system.h"
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
#include "nm-settings.h"
#include "nm-settings-connection.h"
#include "nm-manager-auth.h"
#include "NetworkManagerUtils.h"

#define NM_AUTOIP_DBUS_SERVICE "org.freedesktop.nm_avahi_autoipd"
#define NM_AUTOIP_DBUS_IFACE   "org.freedesktop.nm_avahi_autoipd"

#define UPOWER_DBUS_SERVICE "org.freedesktop.UPower"

static gboolean impl_manager_get_devices (NMManager *manager,
                                          GPtrArray **devices,
                                          GError **err);

static gboolean impl_manager_get_device_by_ip_iface (NMManager *self,
                                                     const char *iface,
                                                     char **out_object_path,
                                                     GError **error);

static void impl_manager_activate_connection (NMManager *manager,
                                              const char *connection_path,
                                              const char *device_path,
                                              const char *specific_object_path,
                                              DBusGMethodInvocation *context);

static void impl_manager_add_and_activate_connection (NMManager *manager,
                                                      GHashTable *settings,
                                                      const char *device_path,
                                                      const char *specific_object_path,
                                                      DBusGMethodInvocation *context);

static void impl_manager_deactivate_connection (NMManager *manager,
                                                const char *connection_path,
                                                DBusGMethodInvocation *context);

static void impl_manager_sleep (NMManager *manager,
                                gboolean do_sleep,
                                DBusGMethodInvocation *context);

static void impl_manager_enable (NMManager *manager,
                                 gboolean enable,
                                 DBusGMethodInvocation *context);

static void impl_manager_get_permissions (NMManager *manager,
                                          DBusGMethodInvocation *context);

static gboolean impl_manager_get_state (NMManager *manager,
                                        guint32 *state,
                                        GError **error);

static gboolean impl_manager_set_logging (NMManager *manager,
                                          const char *level,
                                          const char *domains,
                                          GError **error);

#include "nm-manager-glue.h"

static void udev_device_added_cb (NMUdevManager *udev_mgr,
                                  GUdevDevice *device,
                                  NMDeviceCreatorFn creator_fn,
                                  gpointer user_data);

static void udev_device_removed_cb (NMUdevManager *udev_mgr,
                                    GUdevDevice *device,
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

static const char *internal_activate_device (NMManager *manager,
                                             NMDevice *device,
                                             NMConnection *connection,
                                             const char *specific_object,
                                             gboolean user_requested,
                                             gulong sender_uid,
                                             gboolean assumed,
                                             GError **error);

static NMDevice *find_device_by_ip_iface (NMManager *self, const gchar *iface);

static GSList * remove_one_device (NMManager *manager,
                                   GSList *list,
                                   NMDevice *device,
                                   gboolean quitting);

#define SSD_POKE_INTERVAL 120
#define ORIGDEV_TAG "originating-device"

typedef struct PendingActivation PendingActivation;
typedef void (*PendingActivationFunc) (PendingActivation *pending,
                                       GError *error);

struct PendingActivation {
	NMManager *manager;

	DBusGMethodInvocation *context;
	PendingActivationFunc callback;
	NMAuthChain *chain;

	char *connection_path;
	NMConnection *connection;
	char *specific_object_path;
	char *device_path;
};

typedef struct {
	gboolean user_enabled;
	gboolean daemon_enabled;
	gboolean sw_enabled;
	gboolean hw_enabled;
	RfKillType rtype;
	const char *desc;
	const char *key;
	const char *prop;
	const char *hw_prop;
	RfKillState (*other_enabled_func) (NMManager *);
	RfKillState (*daemon_enabled_func) (NMManager *);
} RadioState;

typedef struct {
	char *config_file;
	char *state_file;

	GSList *devices;
	NMState state;

	NMDBusManager *dbus_mgr;
	NMUdevManager *udev_mgr;
	NMBluezManager *bluez_mgr;

	NMSettings *settings;
	char *hostname;

	RadioState radio_states[RFKILL_TYPE_MAX];
	gboolean sleeping;
	gboolean net_enabled;

	NMVPNManager *vpn_manager;
	guint vpn_manager_id;

	NMModemManager *modem_manager;
	guint modem_added_id;
	guint modem_removed_id;

	DBusGProxy *aipd_proxy;
	DBusGProxy *upower_proxy;

	GSList *auth_chains;

	/* Firmware dir monitor */
	GFileMonitor *fw_monitor;
	guint fw_monitor_id;
	guint fw_changed_id;

	guint timestamp_update_id;

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
	PROPERTIES_CHANGED,
	CHECK_PERMISSIONS,
	USER_PERMISSIONS_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_VERSION,
	PROP_STATE,
	PROP_NETWORKING_ENABLED,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_WWAN_ENABLED,
	PROP_WWAN_HARDWARE_ENABLED,
	PROP_WIMAX_ENABLED,
	PROP_WIMAX_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,

	/* Not exported */
	PROP_HOSTNAME,
	PROP_SLEEPING,

	LAST_PROP
};


/************************************************************************/

typedef enum {
	NM_MANAGER_ERROR_UNKNOWN_CONNECTION = 0,
	NM_MANAGER_ERROR_UNKNOWN_DEVICE,
	NM_MANAGER_ERROR_UNMANAGED_DEVICE,
	NM_MANAGER_ERROR_SYSTEM_CONNECTION,
	NM_MANAGER_ERROR_PERMISSION_DENIED,
	NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
	NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,
	NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED,
	NM_MANAGER_ERROR_UNSUPPORTED_CONNECTION_TYPE,
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
			/* Connection was superceded by a system connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_SYSTEM_CONNECTION, "SystemConnection"),
			/* User does not have the permission to activate this connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			/* The connection was not active. */
			ENUM_ENTRY (NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE, "ConnectionNotActive"),
			/* The manager is already in the requested sleep state */
			ENUM_ENTRY (NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE, "AlreadyAsleepOrAwake"),
			/* The manager is already in the requested enabled/disabled state */
			ENUM_ENTRY (NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED, "AlreadyEnabledOrDisabled"),
			/* The requested operation is unsupported for this type of connection */
			ENUM_ENTRY (NM_MANAGER_ERROR_UNSUPPORTED_CONNECTION_TYPE, "UnsupportedConnectionType"),
			{ 0, 0, 0 },
		};
		etype = g_enum_register_static ("NMManagerError", values);
	}
	return etype;
}

/************************************************************************/

static NMDevice *
nm_manager_get_device_by_udi (NMManager *manager, const char *udi)
{
	GSList *iter;

	g_return_val_if_fail (udi != NULL, NULL);

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

	g_return_val_if_fail (path != NULL, NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		if (!strcmp (nm_device_get_path (NM_DEVICE (iter->data)), path))
			return NM_DEVICE (iter->data);
	}
	return NULL;
}

static gboolean
manager_sleeping (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->sleeping || !priv->net_enabled)
		return TRUE;
	return FALSE;
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
			 NMModem *modem,
			 const char *driver,
			 gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *replace_device, *device = NULL;
	const char *ip_iface;
	GSList *iter;

	ip_iface = nm_modem_get_iface (modem);

	replace_device = find_device_by_ip_iface (NM_MANAGER (user_data), ip_iface);
	if (replace_device) {
		priv->devices = remove_one_device (NM_MANAGER (user_data),
		                                   priv->devices,
		                                   replace_device,
		                                   FALSE);
	}

	/* Give Bluetooth DUN devices first chance to claim the modem */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		if (NM_IS_DEVICE_BT (iter->data)) {
			if (nm_device_bt_modem_added (NM_DEVICE_BT (iter->data), modem, driver))
				return;
		}
	}

	/* If it was a Bluetooth modem and no bluetooth device claimed it, ignore
	 * it.  The rfcomm port (and thus the modem) gets created automatically
	 * by the Bluetooth code during the connection process.
	 */
	if (driver && !strcmp (driver, "bluetooth")) {
		nm_log_info (LOGD_MB, "ignoring modem '%s' (no associated Bluetooth device)", ip_iface);
		return;
	}

	/* Make the new modem device */
	device = nm_device_modem_new (modem, driver);
	if (device)
		add_device (self, device);
}

static void
nm_manager_update_state (NMManager *manager)
{
	NMManagerPrivate *priv;
	NMState new_state = NM_STATE_DISCONNECTED;
	GSList *iter;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (manager_sleeping (manager))
		new_state = NM_STATE_ASLEEP;
	else {
		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *dev = NM_DEVICE (iter->data);
			NMDeviceState state = nm_device_get_state (dev);

			if (state == NM_DEVICE_STATE_ACTIVATED) {
				/* FIXME: handle local-only and site too */
				new_state = NM_STATE_CONNECTED_GLOBAL;
				break;
			}

			if (nm_device_is_activating (dev))
				new_state = NM_STATE_CONNECTING;
			else if (new_state != NM_STATE_CONNECTING) {
				if (state == NM_DEVICE_STATE_DEACTIVATING)
					new_state = NM_STATE_DISCONNECTING;
			}
		}
	}

	if (priv->state != new_state) {
		priv->state = new_state;
		g_object_notify (G_OBJECT (manager), NM_MANAGER_STATE);

		g_signal_emit (manager, signals[STATE_CHANGED], 0, priv->state);
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

	if (new_state == NM_DEVICE_STATE_ACTIVATED) {
		NMActRequest *req;

		req = nm_device_get_act_request (device);
		if (req)
			nm_settings_connection_update_timestamp (NM_SETTINGS_CONNECTION (nm_act_request_get_connection (req)),
			                                         (guint64) time (NULL));
	}
}

/* Removes a device from a device list; returns the start of the new device list */
static GSList *
remove_one_device (NMManager *manager,
                   GSList *list,
                   NMDevice *device,
                   gboolean quitting)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (nm_device_get_managed (device)) {
		/* When quitting, we want to leave up interfaces & connections
		 * that can be taken over again (ie, "assumed") when NM restarts
		 * so that '/etc/init.d/NetworkManager restart' will not distrupt
		 * networking for interfaces that support connection assumption.
		 * All other devices get unmanaged when NM quits so that their
		 * connections get torn down and the interface is deactivated.
		 */

		if (   !nm_device_interface_can_assume_connections (NM_DEVICE_INTERFACE (device))
		    || (nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED)
		    || !quitting)
			nm_device_set_managed (device, FALSE, NM_DEVICE_STATE_REASON_REMOVED);
	}

	g_signal_handlers_disconnect_by_func (device, manager_device_state_changed, manager);

	nm_settings_device_removed (priv->settings, device);
	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, device);
	g_object_unref (device);

	return g_slist_remove (list, device);
}

static void
modem_removed (NMModemManager *modem_manager,
			   NMModem *modem,
			   gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *found;
	GSList *iter;

	/* Give Bluetooth DUN devices first chance to handle the modem removal */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		if (NM_IS_DEVICE_BT (iter->data)) {
			if (nm_device_bt_modem_removed (NM_DEVICE_BT (iter->data), modem))
				return;
		}
	}

	/* Otherwise remove the standalone modem */
	found = nm_manager_get_device_by_udi (self, nm_modem_get_path (modem));
	if (found)
		priv->devices = remove_one_device (self, priv->devices, found, FALSE);
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
	gboolean handled = FALSE;

	if (!event || !iface) {
		nm_log_warn (LOGD_AUTOIP4, "incomplete message received from avahi-autoipd");
		return;
	}

	if (   (strcmp (event, "BIND") != 0)
	    && (strcmp (event, "CONFLICT") != 0)
	    && (strcmp (event, "UNBIND") != 0)
	    && (strcmp (event, "STOP") != 0)) {
		nm_log_warn (LOGD_AUTOIP4, "unknown event '%s' received from avahi-autoipd", event);
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
		nm_log_warn (LOGD_AUTOIP4, "(%s): unhandled avahi-autoipd event", iface);
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

static gboolean
might_be_vpn (NMConnection *connection)
{
	NMSettingConnection *s_con;
	const char *ctype = NULL;

	if (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN))
		return TRUE;

	/* Make sure it's not a VPN, which we can't autocomplete yet */
	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (s_con)
		ctype = nm_setting_connection_get_connection_type (s_con);

	return (g_strcmp0 (ctype, NM_SETTING_VPN_SETTING_NAME) == 0);
}

static gboolean
try_complete_vpn (NMConnection *connection, GSList *existing, GError **error)
{
	g_assert (might_be_vpn (connection) == TRUE);

	if (!nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN)) {
		g_set_error_literal (error,
			                 NM_MANAGER_ERROR,
			                 NM_MANAGER_ERROR_UNSUPPORTED_CONNECTION_TYPE,
			                 "VPN connections require a 'vpn' setting");
		return FALSE;
	}

	nm_utils_complete_generic (connection,
	                           NM_SETTING_VPN_SETTING_NAME,
	                           existing,
	                           _("VPN connection %d"),
	                           NULL,
	                           FALSE); /* No IPv6 by default for now */

	return TRUE;
}

static PendingActivation *
pending_activation_new (NMManager *manager,
                        DBusGMethodInvocation *context,
                        const char *device_path,
                        const char *connection_path,
                        GHashTable *settings,
                        const char *specific_object_path,
                        PendingActivationFunc callback,
                        GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingActivation *pending;
	NMDevice *device = NULL;
	NMConnection *connection = NULL;
	GSList *all_connections = NULL;
	gboolean success;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (context != NULL, NULL);
	g_return_val_if_fail (device_path != NULL, NULL);

	/* A object path of "/" means NULL */
	if (g_strcmp0 (specific_object_path, "/") == 0)
		specific_object_path = NULL;
	if (g_strcmp0 (device_path, "/") == 0)
		device_path = NULL;

	/* Create the partial connection from the given settings */
	if (settings) {
		if (device_path)
			device = nm_manager_get_device_by_path (manager, device_path);
		if (!device) {
			g_set_error_literal (error,
				                 NM_MANAGER_ERROR,
				                 NM_MANAGER_ERROR_UNKNOWN_DEVICE,
				                 "Device not found");
			return NULL;
		}

		connection = nm_connection_new ();
		nm_connection_replace_settings (connection, settings, NULL);

		all_connections = nm_settings_get_connections (priv->settings);

		if (might_be_vpn (connection)) {
			/* Try to fill the VPN's connection setting and name at least */
			success = try_complete_vpn (connection, all_connections, error);
		} else {
			/* Let each device subclass complete the connection */
			success = nm_device_complete_connection (device,
			                                         connection,
			                                         specific_object_path,
			                                         all_connections,
			                                         error);
		}
		g_slist_free (all_connections);

		if (success == FALSE) {
			g_object_unref (connection);
			return NULL;
		}
	}

	pending = g_slice_new0 (PendingActivation);
	pending->manager = manager;
	pending->context = context;
	pending->callback = callback;

	pending->device_path = g_strdup (device_path);
	pending->connection_path = g_strdup (connection_path);
	pending->connection = connection;

	/* "/" is special-cased to NULL to get through D-Bus */
	if (specific_object_path && strcmp (specific_object_path, "/"))
		pending->specific_object_path = g_strdup (specific_object_path);

	return pending;
}

static void
pending_auth_net_done (NMAuthChain *chain,
                       GError *error,
                       DBusGMethodInvocation *context,
                       gpointer user_data)
{
	PendingActivation *pending = user_data;
	NMAuthCallResult result;
	GError *tmp_error = NULL;

	pending->chain = NULL;

	/* Caller has had a chance to obtain authorization, so we only need to
	 * check for 'yes' here.
	 */
	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL));
	if (result != NM_AUTH_CALL_RESULT_YES) {
		tmp_error = g_error_new_literal (NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
		                                 "Not authorized to control networking.");
	}

	pending->callback (pending, tmp_error);
	nm_auth_chain_unref (chain);
	g_clear_error (&tmp_error);
}

static void
pending_activation_check_authorized (PendingActivation *pending,
                                     NMDBusManager *dbus_mgr)
{
	char *error_desc = NULL;
	gulong sender_uid = G_MAXULONG;
	GError *error;

	g_return_if_fail (pending != NULL);
	g_return_if_fail (dbus_mgr != NULL);

	if (!nm_auth_get_caller_uid (pending->context, 
		                         dbus_mgr,
	                             &sender_uid,
	                             &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		pending->callback (pending, error);
		g_error_free (error);
		g_free (error_desc);
		return;
	}

	/* Yay for root */
	if (0 == sender_uid) {
		pending->callback (pending, NULL);
		return;
	}

	/* First check if the user is allowed to use networking at all, giving
	 * the user a chance to authenticate to gain the permission.
	 */
	pending->chain = nm_auth_chain_new (pending->context,
	                                    NULL,
	                                    pending_auth_net_done,
	                                    pending);
	g_assert (pending->chain);
	nm_auth_chain_add_call (pending->chain,
	                        NM_AUTH_PERMISSION_NETWORK_CONTROL,
	                        TRUE);
}

static void
pending_activation_destroy (PendingActivation *pending,
                            GError *error,
                            const char *ac_path)
{
	g_return_if_fail (pending != NULL);

	if (error)
		dbus_g_method_return_error (pending->context, error);
	else if (ac_path) {
		if (pending->connection) {
			dbus_g_method_return (pending->context,
			                      pending->connection_path,
			                      ac_path);
		} else
			dbus_g_method_return (pending->context, ac_path);
	}

	g_free (pending->connection_path);
	g_free (pending->specific_object_path);
	g_free (pending->device_path);
	if (pending->connection)
		g_object_unref (pending->connection);

	if (pending->chain)
		nm_auth_chain_unref (pending->chain);

	memset (pending, 0, sizeof (PendingActivation));
	g_slice_free (PendingActivation, pending);
}

static GPtrArray *
get_active_connections (NMManager *manager, NMConnection *filter)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
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
	nm_vpn_manager_add_active_connections (priv->vpn_manager, filter, active);

	return active;
}

/*******************************************************************/
/* Settings stuff via NMSettings                                   */
/*******************************************************************/

static void
connections_changed (NMSettings *settings,
                     NMSettingsConnection *connection,
                     NMManager *manager)
{
	bluez_manager_resync_devices (manager);
}

static void
system_unmanaged_devices_changed_cb (NMSettings *settings,
                                     GParamSpec *pspec,
                                     gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const GSList *unmanaged_specs, *iter;

	unmanaged_specs = nm_settings_get_unmanaged_specs (priv->settings);
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
system_hostname_changed_cb (NMSettings *settings,
                            GParamSpec *pspec,
                            gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	char *hostname;

	hostname = nm_settings_get_hostname (priv->settings);
	if (!hostname && !priv->hostname)
		return;
	if (hostname && priv->hostname && !strcmp (hostname, priv->hostname))
		return;

	g_free (priv->hostname);
	priv->hostname = (hostname && strlen (hostname)) ? g_strdup (hostname) : NULL;
	g_object_notify (G_OBJECT (self), NM_MANAGER_HOSTNAME);

	g_free (hostname);
}

/*******************************************************************/
/* General NMManager stuff                                         */
/*******************************************************************/

/* Store value into key-file; supported types: boolean, int, string */
static gboolean
write_value_to_state_file (const char *filename,
                           const char *group,
                           const char *key,
                           GType value_type,
                           gpointer value,
                           GError **error)
{
	GKeyFile *key_file;
	char *data;
	gsize len = 0;
	gboolean ret = FALSE;

	g_return_val_if_fail (filename != NULL, FALSE);
	g_return_val_if_fail (group != NULL, FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value_type == G_TYPE_BOOLEAN ||
	                      value_type == G_TYPE_INT ||
	                      value_type == G_TYPE_STRING,
	                      FALSE);

	key_file = g_key_file_new ();
	if (!key_file)
		return FALSE;

	g_key_file_set_list_separator (key_file, ',');
	g_key_file_load_from_file (key_file, filename, G_KEY_FILE_KEEP_COMMENTS, NULL);
	switch (value_type) {
	case G_TYPE_BOOLEAN:
		g_key_file_set_boolean (key_file, group, key, *((gboolean *) value));
		break;
	case G_TYPE_INT:
		g_key_file_set_integer (key_file, group, key, *((gint *) value));
		break;
	case G_TYPE_STRING:
		g_key_file_set_string (key_file, group, key, *((const gchar **) value));
		break;
	}

	data = g_key_file_to_data (key_file, &len, NULL);
	if (data) {
		ret = g_file_set_contents (filename, data, len, error);
		g_free (data);
	}
	g_key_file_free (key_file);

	return ret;
}

static gboolean
radio_enabled_for_rstate (RadioState *rstate, gboolean check_changeable)
{
	gboolean enabled;

	enabled = rstate->user_enabled && rstate->hw_enabled;
	if (check_changeable) {
		enabled &= rstate->sw_enabled;
		if (rstate->daemon_enabled_func)
			enabled &= rstate->daemon_enabled;
	}
	return enabled;
}

static gboolean
radio_enabled_for_type (NMManager *self, RfKillType rtype, gboolean check_changeable)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	return radio_enabled_for_rstate (&priv->radio_states[rtype], check_changeable);
}

static void
manager_update_radio_enabled (NMManager *self,
                              RadioState *rstate,
                              gboolean enabled)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	/* Do nothing for radio types not yet implemented */
	if (!rstate->prop)
		return;

	g_object_notify (G_OBJECT (self), rstate->prop);

	/* Don't touch devices if asleep/networking disabled */
	if (manager_sleeping (self))
		return;

	/* enable/disable wireless devices as required */
	for (iter = priv->devices; iter; iter = iter->next) {
		RfKillType devtype = RFKILL_TYPE_UNKNOWN;

		g_object_get (G_OBJECT (iter->data), NM_DEVICE_INTERFACE_RFKILL_TYPE, &devtype, NULL);
		if (devtype == rstate->rtype) {
			nm_log_dbg (LOGD_RFKILL, "(%s): setting radio %s",
			            nm_device_get_iface (NM_DEVICE (iter->data)),
			            enabled ? "enabled" : "disabled");
			nm_device_interface_set_enabled (NM_DEVICE_INTERFACE (iter->data), enabled);
		}
	}
}

static void
manager_hidden_ap_found (NMDeviceInterface *device,
                         NMAccessPoint *ap,
                         gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
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
	connections = nm_settings_get_connections (priv->settings);

	for (iter = connections; iter && !done; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingWireless *s_wireless;
		const GByteArray *ssid;
		guint32 num_bssids;
		guint32 i;

		s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
		if (!s_wireless)
			continue;

		num_bssids = nm_setting_wireless_get_num_seen_bssids (s_wireless);
		if (num_bssids < 1)
			continue;

		ssid = nm_setting_wireless_get_ssid (s_wireless);
		g_assert (ssid);

		for (i = 0; i < num_bssids && !done; i++) {
			const char *seen_bssid = nm_setting_wireless_get_seen_bssid (s_wireless, i);
			struct ether_addr seen_addr;

			if (ether_aton_r (seen_bssid, &seen_addr)) {
				if (memcmp (ap_addr, &seen_addr, sizeof (struct ether_addr))) {
					/* Copy the SSID from the connection to the AP */
					nm_ap_set_ssid (ap, ssid);
					done = TRUE;
				}
			}
		}
	}
	g_slist_free (connections);
}

static RfKillState
nm_manager_get_ipw_rfkill_state (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	RfKillState ipw_state = RFKILL_UNBLOCKED;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);
		RfKillState candidate_state;

		if (NM_IS_DEVICE_WIFI (candidate)) {
			candidate_state = nm_device_wifi_get_ipw_rfkill_state (NM_DEVICE_WIFI (candidate));

			if (candidate_state > ipw_state)
				ipw_state = candidate_state;
		}
	}

	return ipw_state;
}

static RfKillState
nm_manager_get_modem_enabled_state (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	RfKillState wwan_state = RFKILL_UNBLOCKED;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);
		RfKillState candidate_state = RFKILL_UNBLOCKED;
		RfKillType devtype = RFKILL_TYPE_UNKNOWN;

		g_object_get (G_OBJECT (candidate), NM_DEVICE_INTERFACE_RFKILL_TYPE, &devtype, NULL);
		if (devtype == RFKILL_TYPE_WWAN) {
			if (!nm_device_interface_get_enabled (NM_DEVICE_INTERFACE (candidate)))
				candidate_state = RFKILL_SOFT_BLOCKED;

			if (candidate_state > wwan_state)
				wwan_state = candidate_state;
		}
	}

	return wwan_state;
}

static void
update_rstate_from_rfkill (RadioState *rstate, RfKillState rfkill)
{
	if (rfkill == RFKILL_UNBLOCKED) {
		rstate->sw_enabled = TRUE;
		rstate->hw_enabled = TRUE;
	} else if (rfkill == RFKILL_SOFT_BLOCKED) {
		rstate->sw_enabled = FALSE;
		rstate->hw_enabled = TRUE;
	} else if (rfkill == RFKILL_HARD_BLOCKED) {
		rstate->sw_enabled = FALSE;
		rstate->hw_enabled = FALSE;
	}
}

static void
manager_rfkill_update_one_type (NMManager *self,
                                RadioState *rstate,
                                RfKillType rtype)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	RfKillState udev_state = RFKILL_UNBLOCKED;
	RfKillState other_state = RFKILL_UNBLOCKED;
	RfKillState composite;
	gboolean old_enabled, new_enabled, old_rfkilled, new_rfkilled;
	gboolean old_hwe, old_daemon_enabled = FALSE;

	old_enabled = radio_enabled_for_rstate (rstate, TRUE);
	old_rfkilled = rstate->hw_enabled && rstate->sw_enabled;
	old_hwe = rstate->hw_enabled;

	udev_state = nm_udev_manager_get_rfkill_state (priv->udev_mgr, rtype);

	if (rstate->other_enabled_func)
		other_state = rstate->other_enabled_func (self);

	/* The composite state is the "worst" of either udev or other states */
	if (udev_state == RFKILL_HARD_BLOCKED || other_state == RFKILL_HARD_BLOCKED)
		composite = RFKILL_HARD_BLOCKED;
	else if (udev_state == RFKILL_SOFT_BLOCKED || other_state == RFKILL_SOFT_BLOCKED)
		composite = RFKILL_SOFT_BLOCKED;
	else
		composite = RFKILL_UNBLOCKED;

	update_rstate_from_rfkill (rstate, composite);

	/* If the device has a management daemon that can affect enabled state, check that now */
	if (rstate->daemon_enabled_func) {
		old_daemon_enabled = rstate->daemon_enabled;
		rstate->daemon_enabled = (rstate->daemon_enabled_func (self) == RFKILL_UNBLOCKED);
		if (old_daemon_enabled != rstate->daemon_enabled) {
			nm_log_info (LOGD_RFKILL, "%s now %s by management service",
				         rstate->desc,
				         rstate->daemon_enabled ? "enabled" : "disabled");
		}
	}

	/* Print out all states affecting device enablement */
	if (rstate->desc) {
		if (rstate->daemon_enabled_func) {
			nm_log_dbg (LOGD_RFKILL, "%s hw-enabled %d sw-enabled %d daemon-enabled %d",
			            rstate->desc, rstate->hw_enabled, rstate->sw_enabled, rstate->daemon_enabled);
		} else {
			nm_log_dbg (LOGD_RFKILL, "%s hw-enabled %d sw-enabled %d",
			            rstate->desc, rstate->hw_enabled, rstate->sw_enabled);
		}
	}

	/* Log new killswitch state */
	new_rfkilled = rstate->hw_enabled && rstate->sw_enabled;
	if (old_rfkilled != new_rfkilled) {
		nm_log_info (LOGD_RFKILL, "%s now %s by radio killswitch",
		             rstate->desc,
		             new_rfkilled ? "enabled" : "disabled");
	}

	/* Send out property changed signal for HW enabled */
	if (rstate->hw_enabled != old_hwe) {
		if (rstate->hw_prop)
			g_object_notify (G_OBJECT (self), rstate->hw_prop);
	}

	/* And finally update the actual device radio state itself; respect the
	 * daemon state here because this is never called from user-triggered
	 * radio changes and we only want to ignore the daemon enabled state when
	 * handling user radio change requests.
	 */
	new_enabled = radio_enabled_for_rstate (rstate, TRUE);
	if (new_enabled != old_enabled)
		manager_update_radio_enabled (self, rstate, new_enabled);
}

static void
nm_manager_rfkill_update (NMManager *self, RfKillType rtype)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	guint i;

	if (rtype != RFKILL_TYPE_UNKNOWN)
		manager_rfkill_update_one_type (self, &priv->radio_states[rtype], rtype);
	else {
		/* Otherwise sync all radio types */
		for (i = 0; i < RFKILL_TYPE_MAX; i++)
			manager_rfkill_update_one_type (self, &priv->radio_states[i], i);
	}
}

static void
manager_ipw_rfkill_state_changed (NMDeviceWifi *device,
                                  GParamSpec *pspec,
                                  gpointer user_data)
{
	nm_manager_rfkill_update (NM_MANAGER (user_data), RFKILL_TYPE_WLAN);
}

static void
manager_modem_enabled_changed (NMModem *device, gpointer user_data)
{
	nm_manager_rfkill_update (NM_MANAGER (user_data), RFKILL_TYPE_WWAN);
}

static GError *
deactivate_disconnect_check_error (GError *auth_error,
                                   NMAuthCallResult result,
                                   const char *detail)
{
	if (auth_error) {
		nm_log_dbg (LOGD_CORE, "%s request failed: %s", detail, auth_error->message);
		return g_error_new (NM_MANAGER_ERROR,
		                    NM_MANAGER_ERROR_PERMISSION_DENIED,
		                    "%s request failed: %s",
		                    detail, auth_error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		return g_error_new (NM_MANAGER_ERROR,
		                    NM_MANAGER_ERROR_PERMISSION_DENIED,
		                    "Not authorized to %s connections",
		                    detail);
	}
	return NULL;
}

static void
disconnect_net_auth_done_cb (NMAuthChain *chain,
                             GError *auth_error,
                             DBusGMethodInvocation *context,
                             gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthCallResult result;
	NMDevice *device;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL));
	error = deactivate_disconnect_check_error (auth_error, result, "Disconnect");
	if (!error) {
		device = nm_auth_chain_get_data (chain, "device");
		if (!nm_device_interface_disconnect (NM_DEVICE_INTERFACE (device), &error))
			g_assert (error);
	}

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);

	g_clear_error (&error);
	nm_auth_chain_unref (chain);
}

static void
manager_device_disconnect_request (NMDevice *device,
                                   DBusGMethodInvocation *context,
                                   NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActRequest *req;
	GError *error = NULL;
	gulong sender_uid = G_MAXULONG;
	char *error_desc = NULL;

	req = nm_device_get_act_request (device);
	if (!req) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "This device is not active");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Need to check the caller's permissions and stuff before we can
	 * deactivate the connection.
	 */
	if (!nm_auth_get_caller_uid (context,
		                         priv->dbus_mgr,
	                             &sender_uid,
	                             &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		g_free (error_desc);
		return;
	}

	/* Yay for root */
	if (0 == sender_uid) {
		if (!nm_device_interface_disconnect (NM_DEVICE_INTERFACE (device), &error)) {
			dbus_g_method_return_error (context, error);
			g_clear_error (&error);
		} else
			dbus_g_method_return (context);
	} else {
		NMAuthChain *chain;

		/* Otherwise validate the user request */
		chain = nm_auth_chain_new (context, NULL, disconnect_net_auth_done_cb, self);
		g_assert (chain);
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);

		nm_auth_chain_set_data (chain, "device", g_object_ref (device), g_object_unref);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);
	}
}

static void
add_device (NMManager *self, NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const char *iface, *driver, *type_desc;
	char *path;
	static guint32 devcount = 0;
	const GSList *unmanaged_specs;
	NMConnection *existing = NULL;
	gboolean managed = FALSE, enabled = FALSE;
	RfKillType rtype = RFKILL_TYPE_UNKNOWN;

	iface = nm_device_get_ip_iface (device);
	g_assert (iface);

	if (!NM_IS_DEVICE_MODEM (device) && find_device_by_ip_iface (self, iface)) {
		g_object_unref (device);
		return;
	}

	priv->devices = g_slist_append (priv->devices, device);

	g_signal_connect (device, "state-changed",
					  G_CALLBACK (manager_device_state_changed),
					  self);

	g_signal_connect (device, NM_DEVICE_INTERFACE_DISCONNECT_REQUEST,
					  G_CALLBACK (manager_device_disconnect_request),
					  self);

	if (NM_IS_DEVICE_WIFI (device)) {
		/* Attach to the access-point-added signal so that the manager can fill
		 * non-SSID-broadcasting APs with an SSID.
		 */
		g_signal_connect (device, "hidden-ap-found",
						  G_CALLBACK (manager_hidden_ap_found),
						  self);

		/* Hook up rfkill handling for ipw-based cards until they get converted
		 * to use the kernel's rfkill subsystem in 2.6.33.
		 */
		g_signal_connect (device, "notify::" NM_DEVICE_WIFI_IPW_RFKILL_STATE,
		                  G_CALLBACK (manager_ipw_rfkill_state_changed),
		                  self);
		rtype = RFKILL_TYPE_WLAN;
	} else if (NM_IS_DEVICE_MODEM (device)) {
		g_signal_connect (device, NM_DEVICE_MODEM_ENABLE_CHANGED,
		                  G_CALLBACK (manager_modem_enabled_changed),
		                  self);
		rtype = RFKILL_TYPE_WWAN;
#if WITH_WIMAX
	} else if (NM_IS_DEVICE_WIMAX (device)) {
		rtype = RFKILL_TYPE_WIMAX;
#endif
	}

	if (rtype != RFKILL_TYPE_UNKNOWN) {
		/* Update global rfkill state with this device's rfkill state, and
		 * then set this device's rfkill state based on the global state.
		 */
		nm_manager_rfkill_update (self, rtype);
		enabled = radio_enabled_for_type (self, rtype, TRUE);
		nm_device_interface_set_enabled (NM_DEVICE_INTERFACE (device), enabled);
	}

	type_desc = nm_device_get_type_desc (device);
	g_assert (type_desc);
	driver = nm_device_get_driver (device);
	if (!driver)
		driver = "unknown";
	nm_log_info (LOGD_HW, "(%s): new %s device (driver: '%s' ifindex: %d)",
	             iface, type_desc, driver, nm_device_get_ifindex (device));

	path = g_strdup_printf ("/org/freedesktop/NetworkManager/Devices/%d", devcount++);
	nm_device_set_path (device, path);
	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                     path,
	                                     G_OBJECT (device));
	nm_log_info (LOGD_CORE, "(%s): exported as %s", iface, path);
	g_free (path);

	/* Check if we should assume the device's active connection by matching its
	 * config with an existing system connection.
	 */
	if (nm_device_interface_can_assume_connections (NM_DEVICE_INTERFACE (device))) {
		GSList *connections = NULL;

		connections = nm_settings_get_connections (priv->settings);
		existing = nm_device_interface_connection_match_config (NM_DEVICE_INTERFACE (device),
		                                                        (const GSList *) connections);
		g_slist_free (connections);

		if (existing)
			nm_log_dbg (LOGD_DEVICE, "(%s): found existing device connection '%s'",
			            nm_device_get_iface (device),
			            nm_connection_get_id (existing));
	}

	/* Start the device if it's supposed to be managed */
	unmanaged_specs = nm_settings_get_unmanaged_specs (priv->settings);
	if (   !manager_sleeping (self)
	    && !nm_device_interface_spec_match_list (NM_DEVICE_INTERFACE (device), unmanaged_specs)) {
		nm_device_set_managed (device,
		                       TRUE,
		                       existing ? NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED :
		                                  NM_DEVICE_STATE_REASON_NOW_MANAGED);
		managed = TRUE;
	}

	nm_settings_device_added (priv->settings, device);
	g_signal_emit (self, signals[DEVICE_ADDED], 0, device);

	/* If the device has a connection it can assume, do that now */
	if (existing && managed && nm_device_is_available (device)) {
		const char *ac_path;
		GError *error = NULL;

		nm_log_dbg (LOGD_DEVICE, "(%s): will attempt to assume existing connection",
		            nm_device_get_iface (device));

		ac_path = internal_activate_device (self, device, existing, NULL, FALSE, 0, TRUE, &error);
		if (ac_path)
			g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
		else {
			nm_log_warn (LOGD_DEVICE, "assumed connection %s failed to activate: (%d) %s",
			             nm_connection_get_path (existing),
			             error ? error->code : -1,
			             error && error->message ? error->message : "(unknown)");
			g_error_free (error);
		}
	}
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
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnection *found = NULL;
	GSList *connections, *l;

	connections = nm_settings_get_connections (priv->settings);

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
			gone = remove_one_device (self, gone, NM_DEVICE (gone->data), FALSE);
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
		nm_log_info (LOGD_HW, "BT device %s (%s) added (%s%s%s)",
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

	nm_log_info (LOGD_HW, "BT device %s removed", bdaddr);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_udi (device), object_path)) {
			priv->devices = remove_one_device (self, priv->devices, device, FALSE);
			break;
		}
	}
}

static NMDevice *
find_device_by_ip_iface (NMManager *self, const gchar *iface)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = iter->data;

		if (g_strcmp0 (nm_device_get_ip_iface (candidate), iface) == 0)
			return candidate;
	}
	return NULL;
}

static NMDevice *
find_device_by_ifindex (NMManager *self, guint32 ifindex)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);

		if (ifindex == nm_device_get_ifindex (candidate))
			return candidate;
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
	GObject *device;
	guint32 ifindex;

	ifindex = g_udev_device_get_property_as_int (udev_device, "IFINDEX");
	if (find_device_by_ifindex (self, ifindex))
		return;

	device = creator_fn (udev_mgr, udev_device, manager_sleeping (self));
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
	if (!device) {
		/* On removal we won't always be able to read properties anymore, as
		 * they may have already been removed from sysfs.  Instead, we just
		 * have to fall back to the device's interface name.
		 */
		device = find_device_by_ip_iface (self, g_udev_device_get_name (udev_device));
	}

	if (device)
		priv->devices = remove_one_device (self, priv->devices, device, FALSE);
}

static void
udev_manager_rfkill_changed_cb (NMUdevManager *udev_mgr,
                                RfKillType rtype,
                                RfKillState udev_state,
                                gpointer user_data)
{
	nm_manager_rfkill_update (NM_MANAGER (user_data), rtype);
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

static gboolean
impl_manager_get_device_by_ip_iface (NMManager *self,
                                     const char *iface,
                                     char **out_object_path,
                                     GError **error)
{
	NMDevice *device;
	const char *path = NULL;

	device = find_device_by_ip_iface (self, iface);
	if (device) {
		path = nm_device_get_path (device);
		if (path)
			*out_object_path = g_strdup (path);
	}

	if (path == NULL) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		                     "No device found for the requested iface.");
	}

	return path ? TRUE : FALSE;
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

static const char *
internal_activate_device (NMManager *manager,
                          NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          gboolean user_requested,
                          gulong sender_uid,
                          gboolean assumed,
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

	req = nm_act_request_new (connection,
	                          specific_object,
	                          user_requested,
	                          sender_uid,
	                          assumed,
	                          (gpointer) device);
	success = nm_device_interface_activate (dev_iface, req, error);
	g_object_unref (req);

	return success ? nm_act_request_get_active_connection_path (req) : NULL;
}

const char *
nm_manager_activate_connection (NMManager *manager,
                                NMConnection *connection,
                                const char *specific_object,
                                const char *device_path,
                                const char *dbus_sender,
                                GError **error)
{
	NMManagerPrivate *priv;
	NMDevice *device = NULL;
	NMSettingConnection *s_con;
	NMVPNConnection *vpn_connection;
	const char *path = NULL;
	gulong sender_uid = 0;
	DBusError dbus_error;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);

	/* Get the UID of the user that originated the request, if any */
	if (dbus_sender) {
		dbus_error_init (&dbus_error);
		sender_uid = dbus_bus_get_unix_user (nm_dbus_manager_get_dbus_connection (priv->dbus_mgr),
		                                     dbus_sender,
		                                     &dbus_error);
		if (dbus_error_is_set (&dbus_error)) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR, NM_MANAGER_ERROR_PERMISSION_DENIED,
			                     "Failed to get unix user for dbus sender");
			dbus_error_free (&dbus_error);
			return NULL;
		}
	}

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (!strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_VPN_SETTING_NAME)) {
		NMActRequest *parent_req = NULL;

		/* VPN connection */

		if (specific_object) {
			/* Find the specifc connection the client requested we use */
			parent_req = nm_manager_get_act_request_by_path (manager, specific_object, &device);
			if (!parent_req) {
				g_set_error (error,
				             NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
				             "%s", "Base connection for VPN connection not active.");
				return NULL;
			}
		} else {
			GSList *iter;

			/* Just find the current default connection */
			for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
				NMDevice *candidate = NM_DEVICE (iter->data);
				NMActRequest *candidate_req;

				candidate_req = nm_device_get_act_request (candidate);
				if (candidate_req && nm_act_request_get_default (candidate_req)) {
					device = candidate;
					parent_req = candidate_req;
					break;
				}
			}
		}

		if (!device || !parent_req) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "%s", "Could not find source connection, or the source connection had no active device.");
			return NULL;
		}

		vpn_connection = nm_vpn_manager_activate_connection (priv->vpn_manager,
		                                                     connection,
		                                                     device,
		                                                     TRUE,
		                                                     sender_uid,
		                                                     error);
		if (vpn_connection)
			path = nm_vpn_connection_get_active_connection_path (vpn_connection);
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
			             "%s", "Device not managed by NetworkManager or unavailable");
			return NULL;
		}

		path = internal_activate_device (manager,
		                                 device,
		                                 connection,
		                                 specific_object,
		                                 dbus_sender ? TRUE : FALSE,
		                                 dbus_sender ? sender_uid : 0,
		                                 FALSE,
		                                 error);
	}

	return path;
}

/* 
 * TODO this function was created and named in the era of user settings, where
 * we could get activation requests for a connection before we got the settings
 * data of that connection. Now that user settings are gone, flatten or rename
 * it.
 */
static void
pending_activate (NMManager *self, PendingActivation *pending)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMSettingsConnection *connection;
	const char *path = NULL;
	GError *error = NULL;
	char *sender;

	/* Ok, we're authorized */

	connection = nm_settings_get_connection_by_path (priv->settings, pending->connection_path);
	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "Connection could not be found.");
		goto out;
	}

	sender = dbus_g_method_get_sender (pending->context);
	g_assert (sender);
	path = nm_manager_activate_connection (self,
	                                       NM_CONNECTION (connection),
	                                       pending->specific_object_path,
	                                       pending->device_path,
	                                       sender,
	                                       &error);
	g_free (sender);

	if (!path) {
		nm_log_warn (LOGD_CORE, "connection %s failed to activate: (%d) %s",
		             pending->connection_path, error->code, error->message);
	} else
		g_object_notify (G_OBJECT (pending->manager), NM_MANAGER_ACTIVE_CONNECTIONS);

out:
	pending_activation_destroy (pending, error, path);
	g_clear_error (&error);
}

static void
activation_auth_done (PendingActivation *pending, GError *error)
{
	if (error)
		pending_activation_destroy (pending, error, NULL);
	else
		pending_activate (pending->manager, pending);
}

static void
impl_manager_activate_connection (NMManager *self,
                                  const char *connection_path,
                                  const char *device_path,
                                  const char *specific_object_path,
                                  DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	PendingActivation *pending;
	GError *error = NULL;

	/* Need to check the caller's permissions and stuff before we can
	 * activate the connection.
	 */
	pending = pending_activation_new (self,
	                                  context,
	                                  device_path,
	                                  connection_path,
	                                  NULL,
	                                  specific_object_path,
	                                  activation_auth_done,
	                                  &error);
	if (pending)
		pending_activation_check_authorized (pending, priv->dbus_mgr);
	else {
		g_assert (error);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

static void
activation_add_done (NMSettings *self,
                     NMSettingsConnection *connection,
                     GError *error,
                     DBusGMethodInvocation *context,
                     gpointer user_data)
{
	PendingActivation *pending = user_data;

	if (error)
		pending_activation_destroy (pending, error, NULL);
	else {
		/* Save the new connection's D-Bus path */
		pending->connection_path = g_strdup (nm_connection_get_path (NM_CONNECTION (connection)));

		/* And activate it */
		pending_activate (pending->manager, pending);
	}
}

static void
add_and_activate_auth_done (PendingActivation *pending, GError *error)
{
	if (error)
		pending_activation_destroy (pending, error, NULL);
	else {
		NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (pending->manager);

		/* Basic sender auth checks performed; try to add the connection */
		nm_settings_add_connection (priv->settings,
                                    pending->connection,
                                    pending->context,
                                    activation_add_done,
                                    pending);
	}
}

static void
impl_manager_add_and_activate_connection (NMManager *self,
                                          GHashTable *settings,
                                          const char *device_path,
                                          const char *specific_object_path,
                                          DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	PendingActivation *pending;
	GError *error = NULL;

	/* Need to check the caller's permissions and stuff before we can
	 * activate the connection.
	 */
	pending = pending_activation_new (self,
	                                  context,
	                                  device_path,
	                                  NULL,
	                                  settings,
	                                  specific_object_path,
	                                  add_and_activate_auth_done,
	                                  &error);
	if (pending)
		pending_activation_check_authorized (pending, priv->dbus_mgr);
	else {
		g_assert (error);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

gboolean
nm_manager_deactivate_connection (NMManager *manager,
                                  const char *connection_path,
                                  NMDeviceStateReason reason,
                                  GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
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
	if (reason == NM_DEVICE_STATE_REASON_CONNECTION_REMOVED)
		vpn_reason = NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED;
	if (nm_vpn_manager_deactivate_connection (priv->vpn_manager, connection_path, vpn_reason)) {
		success = TRUE;
	} else {
		g_set_error (error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
		             "%s", "The connection was not active.");
	}

done:
	g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
	return success;
}

static void
deactivate_net_auth_done_cb (NMAuthChain *chain,
                             GError *auth_error,
                             DBusGMethodInvocation *context,
                             gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthCallResult result;
	const char *active_path;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL));
	error = deactivate_disconnect_check_error (auth_error, result, "Deactivate");
	if (!error) {
		active_path = nm_auth_chain_get_data (chain, "path");
		if (!nm_manager_deactivate_connection (self,
		                                       active_path,
		                                       NM_DEVICE_STATE_REASON_USER_REQUESTED,
		                                       &error))
			g_assert (error);
	}

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);

	g_clear_error (&error);
	nm_auth_chain_unref (chain);
}

static void
impl_manager_deactivate_connection (NMManager *self,
                                    const char *active_path,
                                    DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMConnection *connection = NULL;
	GError *error = NULL;
	GSList *iter;
	NMAuthChain *chain;
	gulong sender_uid = G_MAXULONG;
	char *error_desc = NULL;

	/* Check for device connections first */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMActRequest *req;
		const char *req_path = NULL;

		req = nm_device_get_act_request (NM_DEVICE (iter->data));
		if (req)
			req_path = nm_act_request_get_active_connection_path (req);

		if (req_path && !strcmp (active_path, req_path)) {
			connection = nm_act_request_get_connection (req);
			break;
		}
	}

	/* Maybe it's a VPN */
	if (!connection)
		connection = nm_vpn_manager_get_connection_for_active (priv->vpn_manager, active_path);

	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
		                             "The connection was not active.");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Need to check the caller's permissions and stuff before we can
	 * deactivate the connection.
	 */
	if (!nm_auth_get_caller_uid (context, 
		                         priv->dbus_mgr,
	                             &sender_uid,
	                             &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		g_free (error_desc);
		return;
	}

	/* Yay for root */
	if (0 == sender_uid) {
		if (!nm_manager_deactivate_connection (self,
		                                       active_path,
		                                       NM_DEVICE_STATE_REASON_USER_REQUESTED,
		                                       &error)) {
			dbus_g_method_return_error (context, error);
			g_clear_error (&error);
		} else
			dbus_g_method_return (context);

		return;
	}

	/* Otherwise validate the user request */
	chain = nm_auth_chain_new (context, NULL, deactivate_net_auth_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_set_data (chain, "path", g_strdup (active_path), g_free);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);
}

static void
do_sleep_wake (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const GSList *unmanaged_specs;
	GSList *iter;

	if (manager_sleeping (self)) {
		nm_log_info (LOGD_SUSPEND, "sleeping or disabling...");

		/* Just deactivate and down all devices from the device list,
		 * to keep things fast the device list will get resynced when
		 * the manager wakes up.
		 */
		for (iter = priv->devices; iter; iter = iter->next)
			nm_device_set_managed (NM_DEVICE (iter->data), FALSE, NM_DEVICE_STATE_REASON_SLEEPING);

	} else {
		nm_log_info (LOGD_SUSPEND, "waking up and re-enabling...");

		unmanaged_specs = nm_settings_get_unmanaged_specs (priv->settings);

		/* Ensure rfkill state is up-to-date since we don't respond to state
		 * changes during sleep.
		 */
		nm_manager_rfkill_update (self, RFKILL_TYPE_UNKNOWN);

		/* Re-manage managed devices */
		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *device = NM_DEVICE (iter->data);
			guint i;

			/* enable/disable wireless devices since that we don't respond
			 * to killswitch changes during sleep.
			 */
			for (i = 0; i < RFKILL_TYPE_MAX; i++) {
				RadioState *rstate = &priv->radio_states[i];
				gboolean enabled = radio_enabled_for_rstate (rstate, TRUE);
				RfKillType devtype = RFKILL_TYPE_UNKNOWN;

				if (rstate->desc) {
					nm_log_dbg (LOGD_RFKILL, "%s %s devices (hw_enabled %d, sw_enabled %d, user_enabled %d)",
					            enabled ? "enabling" : "disabling",
					            rstate->desc, rstate->hw_enabled, rstate->sw_enabled, rstate->user_enabled);
				}

				g_object_get (G_OBJECT (device), NM_DEVICE_INTERFACE_RFKILL_TYPE, &devtype, NULL);
				if (devtype == rstate->rtype)
					nm_device_interface_set_enabled (NM_DEVICE_INTERFACE (device), enabled);
			}

			nm_device_clear_autoconnect_inhibit (device);
			if (nm_device_interface_spec_match_list (NM_DEVICE_INTERFACE (device), unmanaged_specs))
				nm_device_set_managed (device, FALSE, NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
			else
				nm_device_set_managed (device, TRUE, NM_DEVICE_STATE_REASON_NOW_MANAGED);
		}

		/* Ask for new bluetooth devices */
		bluez_manager_resync_devices (self);
	}

	nm_manager_update_state (self);
}

static void
_internal_sleep (NMManager *self, gboolean do_sleep)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->sleeping == do_sleep)
		return;

	nm_log_info (LOGD_SUSPEND, "%s requested (sleeping: %s  enabled: %s)",
	             do_sleep ? "sleep" : "wake",
	             priv->sleeping ? "yes" : "no",
	             priv->net_enabled ? "yes" : "no");

	priv->sleeping = do_sleep;

	do_sleep_wake (self);

	g_object_notify (G_OBJECT (self), NM_MANAGER_SLEEPING);
}

#if 0
static void
sleep_auth_done_cb (NMAuthChain *chain,
                    GError *error,
                    DBusGMethodInvocation *context,
                    gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error;
	NMAuthCallResult result;
	gboolean do_sleep;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_SLEEP_WAKE));
	if (error) {
		nm_log_dbg (LOGD_SUSPEND, "Sleep/wake request failed: %s", error->message);
		ret_error = g_error_new (NM_MANAGER_ERROR,
		                         NM_MANAGER_ERROR_PERMISSION_DENIED,
		                         "Sleep/wake request failed: %s",
		                         error->message);
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		ret_error = g_error_new_literal (NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
		                                 "Not authorized to sleep/wake");
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
	} else {
		/* Auth success */
		do_sleep = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "sleep"));
		_internal_sleep (self, do_sleep);
		dbus_g_method_return (context);
	}

	nm_auth_chain_unref (chain);
}
#endif

static void
impl_manager_sleep (NMManager *self,
                    gboolean do_sleep,
                    DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv;
	GError *error = NULL;
#if 0
	NMAuthChain *chain;
	gulong sender_uid = G_MAXULONG;
	const char *error_desc = NULL;
#endif

	g_return_if_fail (NM_IS_MANAGER (self));

	priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->sleeping == do_sleep) {
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,
		                     "Already %s", do_sleep ? "asleep" : "awake");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Unconditionally allow the request.  Previously it was polkit protected
	 * but unfortunately that doesn't work for short-lived processes like
	 * pm-utils.  It uses dbus-send without --print-reply, which quits
	 * immediately after sending the request, and NM is unable to obtain the
	 * sender's UID as dbus-send has already dropped off the bus.  Thus NM
	 * fails the request.  Instead, don't validate the request, but rely on
	 * D-Bus permissions to restrict the call to root.
	 */
	_internal_sleep (self, do_sleep);
	dbus_g_method_return (context);
	return;

#if 0
	if (!nm_auth_get_caller_uid (context, priv->dbus_mgr, &sender_uid, &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Root doesn't need PK authentication */
	if (0 == sender_uid) {
		_internal_sleep (self, do_sleep);
		dbus_g_method_return (context);
		return;
	}

	chain = nm_auth_chain_new (context, NULL, sleep_auth_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_set_data (chain, "sleep", GUINT_TO_POINTER (do_sleep), NULL);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SLEEP_WAKE, TRUE);
#endif
}

static void
upower_sleeping_cb (DBusGProxy *proxy, gpointer user_data)
{
	nm_log_dbg (LOGD_SUSPEND, "Received UPower sleeping signal");
	_internal_sleep (NM_MANAGER (user_data), TRUE);
}

static void
upower_resuming_cb (DBusGProxy *proxy, gpointer user_data)
{
	nm_log_dbg (LOGD_SUSPEND, "Received UPower resuming signal");
	_internal_sleep (NM_MANAGER (user_data), FALSE);
}

static void
_internal_enable (NMManager *self, gboolean enable)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *err = NULL;

	/* Update "NetworkingEnabled" key in state file */
	if (priv->state_file) {
		if (!write_value_to_state_file (priv->state_file,
		                                "main", "NetworkingEnabled",
		                                G_TYPE_BOOLEAN, (gpointer) &enable,
		                                &err)) {
			/* Not a hard error */
			nm_log_warn (LOGD_SUSPEND, "writing to state file %s failed: (%d) %s.",
			             priv->state_file,
			             err ? err->code : -1,
			             (err && err->message) ? err->message : "unknown");
		}
	}

	nm_log_info (LOGD_SUSPEND, "%s requested (sleeping: %s  enabled: %s)",
	             enable ? "enable" : "disable",
	             priv->sleeping ? "yes" : "no",
	             priv->net_enabled ? "yes" : "no");

	priv->net_enabled = enable;

	do_sleep_wake (self);

	g_object_notify (G_OBJECT (self), NM_MANAGER_NETWORKING_ENABLED);
}

static void
enable_net_done_cb (NMAuthChain *chain,
                    GError *error,
                    DBusGMethodInvocation *context,
                    gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error;
	NMAuthCallResult result;
	gboolean enable;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK));
	if (error) {
		nm_log_dbg (LOGD_CORE, "Enable request failed: %s", error->message);
		ret_error = g_error_new (NM_MANAGER_ERROR,
		                         NM_MANAGER_ERROR_PERMISSION_DENIED,
		                         "Enable request failed: %s",
		                         error->message);
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		ret_error = g_error_new_literal (NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
		                                 "Not authorized to enable/disable networking");
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
	} else {
		/* Auth success */
		enable = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "enable"));
		_internal_enable (self, enable);
		dbus_g_method_return (context);
	}

	nm_auth_chain_unref (chain);
}

static void
impl_manager_enable (NMManager *self,
                     gboolean enable,
                     DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv;
	NMAuthChain *chain;
	GError *error = NULL;
	gulong sender_uid = G_MAXULONG;
	char *error_desc = NULL;

	g_return_if_fail (NM_IS_MANAGER (self));

	priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->net_enabled == enable) {
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED,
		                     "Already %s", enable ? "enabled" : "disabled");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	if (!nm_auth_get_caller_uid (context, priv->dbus_mgr, &sender_uid, &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		g_free (error_desc);
		return;
	}

	/* Root doesn't need PK authentication */
	if (0 == sender_uid) {
		_internal_enable (self, enable);
		dbus_g_method_return (context);
		return;
	}

	chain = nm_auth_chain_new (context, NULL, enable_net_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_set_data (chain, "enable", GUINT_TO_POINTER (enable), NULL);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK, TRUE);
}

/* Permissions */

static void
get_perm_add_result (NMAuthChain *chain, GHashTable *results, const char *permission)
{
	NMAuthCallResult result;

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, permission));
	if (result == NM_AUTH_CALL_RESULT_YES)
		g_hash_table_insert (results, (char *) permission, "yes");
	else if (result == NM_AUTH_CALL_RESULT_NO)
		g_hash_table_insert (results, (char *) permission, "no");
	else if (result == NM_AUTH_CALL_RESULT_AUTH)
		g_hash_table_insert (results, (char *) permission, "auth");
	else {
		nm_log_dbg (LOGD_CORE, "unknown auth chain result %d", result);
	}
}

static void
get_permissions_done_cb (NMAuthChain *chain,
                         GError *error,
                         DBusGMethodInvocation *context,
                         gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error;
	GHashTable *results;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);
	if (error) {
		nm_log_dbg (LOGD_CORE, "Permissions request failed: %s", error->message);
		ret_error = g_error_new (NM_MANAGER_ERROR,
		                         NM_MANAGER_ERROR_PERMISSION_DENIED,
		                         "Permissions request failed: %s",
		                         error->message);
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
	} else {
		results = g_hash_table_new (g_str_hash, g_str_equal);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_SLEEP_WAKE);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_NETWORK_CONTROL);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME);
		dbus_g_method_return (context, results);
		g_hash_table_destroy (results);
	}

	nm_auth_chain_unref (chain);
}

static void
impl_manager_get_permissions (NMManager *self,
                              DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMAuthChain *chain;

	chain = nm_auth_chain_new (context, NULL, get_permissions_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SLEEP_WAKE, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME, FALSE);
}

static gboolean
impl_manager_get_state (NMManager *manager, guint32 *state, GError **error)
{
	nm_manager_update_state (manager);
	*state = NM_MANAGER_GET_PRIVATE (manager)->state;
	return TRUE;
}

static gboolean
impl_manager_set_logging (NMManager *manager,
                          const char *level,
                          const char *domains,
                          GError **error)
{
	if (nm_logging_setup (level, domains, error)) {
		char *new_domains = nm_logging_domains_to_string ();

		nm_log_info (LOGD_CORE, "logging: level '%s' domains '%s'",
		             nm_logging_level_to_string (),
		             new_domains);
		g_free (new_domains);
		return TRUE;
	}
	return FALSE;
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
	guint i;

	/* Set initial radio enabled/disabled state */
	for (i = 0; i < RFKILL_TYPE_MAX; i++) {
		RadioState *rstate = &priv->radio_states[i];
		RfKillState udev_state;
		gboolean enabled;

		if (!rstate->desc)
			continue;

		udev_state = nm_udev_manager_get_rfkill_state (priv->udev_mgr, i);
		update_rstate_from_rfkill (rstate, udev_state);

		if (rstate->desc) {
			nm_log_info (LOGD_RFKILL, "%s %s by radio killswitch; %s by state file",
				         rstate->desc,
				         (rstate->hw_enabled && rstate->sw_enabled) ? "enabled" : "disabled",
				         rstate->user_enabled ? "enabled" : "disabled");
		}
		enabled = radio_enabled_for_rstate (rstate, TRUE);
		manager_update_radio_enabled (self, rstate, enabled);
	}

	/* Log overall networking status - enabled/disabled */
	nm_log_info (LOGD_CORE, "Networking is %s by state file",
	             priv->net_enabled ? "enabled" : "disabled");

	system_unmanaged_devices_changed_cb (priv->settings, NULL, self);
	system_hostname_changed_cb (priv->settings, NULL, self);

	nm_udev_manager_query_devices (priv->udev_mgr);
	bluez_manager_resync_devices (self);
}

static gboolean
handle_firmware_changed (gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	priv->fw_changed_id = 0;

	if (manager_sleeping (self))
		return FALSE;

	/* Try to re-enable devices with missing firmware */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = NM_DEVICE (iter->data);
		NMDeviceState state = nm_device_get_state (candidate);

		if (   nm_device_get_firmware_missing (candidate)
		    && (state == NM_DEVICE_STATE_UNAVAILABLE)) {
			nm_log_info (LOGD_CORE, "(%s): firmware may now be available",
			             nm_device_get_iface (candidate));

			/* Re-set unavailable state to try bringing the device up again */
			nm_device_state_changed (candidate,
			                         NM_DEVICE_STATE_UNAVAILABLE,
			                         NM_DEVICE_STATE_REASON_NONE);
		}
	}

	return FALSE;
}

static void
firmware_dir_changed (GFileMonitor *monitor,
                      GFile *file,
                      GFile *other_file,
                      GFileMonitorEvent event_type,
                      gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_CREATED:
	case G_FILE_MONITOR_EVENT_CHANGED:
#if GLIB_CHECK_VERSION(2,23,4)
	case G_FILE_MONITOR_EVENT_MOVED:
#endif
	case G_FILE_MONITOR_EVENT_ATTRIBUTE_CHANGED:
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		if (!priv->fw_changed_id) {
			priv->fw_changed_id = g_timeout_add_seconds (4, handle_firmware_changed, self);
			nm_log_info (LOGD_CORE, "kernel firmware directory '%s' changed",
			             KERNEL_FIRMWARE_DIR);
		}
		break;
	default:
		break;
	}
}

#define PERM_DENIED_ERROR "org.freedesktop.NetworkManager.PermissionDenied"

static void
prop_set_auth_done_cb (NMAuthChain *chain,
                       GError *error,
                       DBusGMethodInvocation *context,
                       gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	DBusGConnection *bus;
	DBusConnection *dbus_connection;
	NMAuthCallResult result;
	DBusMessage *reply, *request;
	const char *permission, *prop;
	gboolean set_enabled = TRUE;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	request = nm_auth_chain_get_data (chain, "message");
	permission = nm_auth_chain_get_data (chain, "permission");
	prop = nm_auth_chain_get_data (chain, "prop");
	set_enabled = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "enabled"));

	if (error) {
		reply = dbus_message_new_error (request, PERM_DENIED_ERROR,
		                                "Not authorized to perform this operation");
	} else {
		/* Caller has had a chance to obtain authorization, so we only need to
		 * check for 'yes' here.
		 */
		result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, permission));
		if (result != NM_AUTH_CALL_RESULT_YES) {
			reply = dbus_message_new_error (request, PERM_DENIED_ERROR,
				                            "Not authorized to perform this operation");
		} else {
			g_object_set (self, prop, set_enabled, NULL);
			reply = dbus_message_new_method_return (request);
		}
	}

	if (reply) {
		bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
		g_assert (bus);
		dbus_connection = dbus_g_connection_get_connection (bus);
		g_assert (dbus_connection);

		dbus_connection_send (dbus_connection, reply, NULL);
		dbus_message_unref (reply);
	}
	nm_auth_chain_unref (chain);
}

static DBusHandlerResult
prop_filter (DBusConnection *connection,
             DBusMessage *message,
             void *user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	DBusMessageIter iter;
	DBusMessageIter sub;
	const char *propiface = NULL;
	const char *propname = NULL;
	const char *sender = NULL;
	const char *glib_propname = NULL, *permission = NULL;
	DBusError dbus_error;
	gulong uid = G_MAXULONG;
	DBusMessage *reply = NULL;
	gboolean set_enabled = FALSE;
	NMAuthChain *chain;

	/* The sole purpose of this function is to validate property accesses
	 * on the NMManager object since dbus-glib doesn't yet give us this
	 * functionality.
	 */

	if (!dbus_message_is_method_call (message, DBUS_INTERFACE_PROPERTIES, "Set"))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	dbus_message_iter_init (message, &iter);

	/* Get the D-Bus interface of the property to set */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_message_iter_get_basic (&iter, &propiface);
	if (!propiface || strcmp (propiface, NM_DBUS_INTERFACE))
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_message_iter_next (&iter);

	/* Get the property name that's going to be set */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_STRING)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_message_iter_get_basic (&iter, &propname);
	dbus_message_iter_next (&iter);

	if (!strcmp (propname, "WirelessEnabled")) {
		glib_propname = NM_MANAGER_WIRELESS_ENABLED;
		permission = NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI;
	} else if (!strcmp (propname, "WwanEnabled")) {
		glib_propname = NM_MANAGER_WWAN_ENABLED;
		permission = NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN;
	} else if (!strcmp (propname, "WimaxEnabled")) {
		glib_propname = NM_MANAGER_WIMAX_ENABLED;
		permission = NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX;
	} else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	/* Get the new value for the property */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_VARIANT)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_message_iter_recurse (&iter, &sub);
	if (dbus_message_iter_get_arg_type (&sub) != DBUS_TYPE_BOOLEAN)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_message_iter_get_basic (&sub, &set_enabled);

	sender = dbus_message_get_sender (message);
	if (!sender) {
		reply = dbus_message_new_error (message, PERM_DENIED_ERROR,
		                                "Could not determine D-Bus requestor");
		goto out;
	}

	dbus_error_init (&dbus_error);
	uid = dbus_bus_get_unix_user (connection, sender, &dbus_error);
	if (dbus_error_is_set (&dbus_error)) {
		reply = dbus_message_new_error (message, PERM_DENIED_ERROR,
		                                "Could not determine the user ID of the requestor");
		dbus_error_free (&dbus_error);
		goto out;
	}

	if (uid > 0) {
		/* Otherwise validate the user request */
		chain = nm_auth_chain_new_raw_message (message, prop_set_auth_done_cb, self);
		g_assert (chain);
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);
		nm_auth_chain_set_data (chain, "prop", g_strdup (glib_propname), g_free);
		nm_auth_chain_set_data (chain, "permission", g_strdup (permission), g_free);
		nm_auth_chain_set_data (chain, "enabled", GUINT_TO_POINTER (set_enabled), NULL);
		nm_auth_chain_set_data (chain, "message", dbus_message_ref (message), (GDestroyNotify) dbus_message_unref);
		nm_auth_chain_add_call (chain, permission, TRUE);
	} else {
		/* Yay for root */
		g_object_set (self, glib_propname, set_enabled, NULL);
		reply = dbus_message_new_method_return (message);
	}

out:
	if (reply) {
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

NMManager *
nm_manager_get (NMSettings *settings,
                const char *config_file,
                const char *plugins,
                const char *state_file,
                gboolean initial_net_enabled,
                gboolean initial_wifi_enabled,
                gboolean initial_wwan_enabled,
                gboolean initial_wimax_enabled,
                GError **error)
{
	static NMManager *singleton = NULL;
	NMManagerPrivate *priv;
	DBusGConnection *bus;
	DBusConnection *dbus_connection;

	if (singleton)
		return g_object_ref (singleton);

	g_assert (settings);

	singleton = (NMManager *) g_object_new (NM_TYPE_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_MANAGER_GET_PRIVATE (singleton);

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	g_assert (bus);
	dbus_connection = dbus_g_connection_get_connection (bus);
	g_assert (dbus_connection);

	if (!dbus_connection_add_filter (dbus_connection, prop_filter, singleton, NULL)) {
		nm_log_err (LOGD_CORE, "failed to register DBus connection filter");
		g_object_unref (singleton);
		return NULL;
    }

	priv->settings = g_object_ref (settings);

	priv->config_file = g_strdup (config_file);
	priv->state_file = g_strdup (state_file);

	priv->net_enabled = initial_net_enabled;

	priv->radio_states[RFKILL_TYPE_WLAN].user_enabled = initial_wifi_enabled;
	priv->radio_states[RFKILL_TYPE_WWAN].user_enabled = initial_wwan_enabled;
	priv->radio_states[RFKILL_TYPE_WIMAX].user_enabled = initial_wimax_enabled;

	g_signal_connect (priv->settings, "notify::" NM_SETTINGS_UNMANAGED_SPECS,
	                  G_CALLBACK (system_unmanaged_devices_changed_cb), singleton);
	g_signal_connect (priv->settings, "notify::" NM_SETTINGS_HOSTNAME,
	                  G_CALLBACK (system_hostname_changed_cb), singleton);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (connections_changed), singleton);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (connections_changed), singleton);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (connections_changed), singleton);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_VISIBILITY_CHANGED,
	                  G_CALLBACK (connections_changed), singleton);

	dbus_g_connection_register_g_object (bus, NM_DBUS_PATH, G_OBJECT (singleton));

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
	DBusGConnection *bus;
	DBusConnection *dbus_connection;

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_slist_foreach (priv->auth_chains, (GFunc) nm_auth_chain_unref, NULL);
	g_slist_free (priv->auth_chains);

	nm_auth_set_changed_func (NULL, NULL);

	while (g_slist_length (priv->devices)) {
		priv->devices = remove_one_device (manager,
		                                   priv->devices,
		                                   NM_DEVICE (priv->devices->data),
		                                   TRUE);
	}

	g_free (priv->hostname);
	g_free (priv->config_file);

	g_object_unref (priv->settings);

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

	/* Unregister property filter */
	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (bus) {
		dbus_connection = dbus_g_connection_get_connection (bus);
		g_assert (dbus_connection);
		dbus_connection_remove_filter (dbus_connection, prop_filter, manager);
	}
	g_object_unref (priv->dbus_mgr);

	if (priv->bluez_mgr)
		g_object_unref (priv->bluez_mgr);

	if (priv->aipd_proxy)
		g_object_unref (priv->aipd_proxy);

	if (priv->upower_proxy)
		g_object_unref (priv->upower_proxy);

	if (priv->fw_monitor) {
		if (priv->fw_monitor_id)
			g_signal_handler_disconnect (priv->fw_monitor, priv->fw_monitor_id);

		if (priv->fw_changed_id)
			g_source_remove (priv->fw_changed_id);

		g_file_monitor_cancel (priv->fw_monitor);
		g_object_unref (priv->fw_monitor);
	}

	if (priv->timestamp_update_id) {
		g_source_remove (priv->timestamp_update_id);
		priv->timestamp_update_id = 0;
	}

	G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
}

#define KERN_RFKILL_OP_CHANGE_ALL 3
#define KERN_RFKILL_TYPE_WLAN     1
struct rfkill_event {
	__u32 idx;
	__u8  type;
	__u8  op;
	__u8  soft, hard;
} __attribute__((packed));

static void
rfkill_change_wifi (const char *desc, gboolean enabled)
{
	int fd;
	struct rfkill_event event;
	ssize_t len;

	errno = 0;
	fd = open ("/dev/rfkill", O_RDWR);
	if (fd < 0) {
		if (errno == EACCES)
			nm_log_warn (LOGD_RFKILL, "(%s): failed to open killswitch device "
			             "for WiFi radio control", desc);
		return;
	}

	if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0) {
		nm_log_warn (LOGD_RFKILL, "(%s): failed to set killswitch device for "
		             "non-blocking operation", desc);
		close (fd);
		return;
	}

	memset (&event, 0, sizeof (event));
	event.op = KERN_RFKILL_OP_CHANGE_ALL;
	event.type = KERN_RFKILL_TYPE_WLAN;
	event.soft = enabled ? 0 : 1;

	len = write (fd, &event, sizeof (event));
	if (len < 0) {
		nm_log_warn (LOGD_RFKILL, "(%s): failed to change WiFi killswitch state: (%d) %s",
		             desc, errno, g_strerror (errno));
	} else if (len == sizeof (event)) {
		nm_log_info (LOGD_RFKILL, "%s hardware radio set %s",
		             desc, enabled ? "enabled" : "disabled");
	} else {
		/* Failed to write full structure */
		nm_log_warn (LOGD_RFKILL, "(%s): failed to change WiFi killswitch state", desc);
	}

	close (fd);
}

static void
manager_radio_user_toggled (NMManager *self,
                            RadioState *rstate,
                            gboolean enabled)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	gboolean old_enabled, new_enabled;

	if (rstate->desc) {
		nm_log_dbg (LOGD_RFKILL, "(%s): setting radio %s by user",
		            rstate->desc,
		            enabled ? "enabled" : "disabled");
	}

	/* Update enabled key in state file */
	if (priv->state_file) {
		if (!write_value_to_state_file (priv->state_file,
		                                "main", rstate->key,
		                                G_TYPE_BOOLEAN, (gpointer) &enabled,
		                                &error)) {
			nm_log_warn (LOGD_CORE, "writing to state file %s failed: (%d) %s.",
			             priv->state_file,
			             error ? error->code : -1,
			             (error && error->message) ? error->message : "unknown");
			g_clear_error (&error);
		}
	}

	/* When the user toggles the radio, their request should override any
	 * daemon (like ModemManager) enabled state that can be changed.  For WWAN
	 * for example, we want the WwanEnabled property to reflect the daemon state
	 * too so that users can toggle the modem powered, but we don't want that
	 * daemon state to affect whether or not the user *can* turn it on, which is
	 * what the kernel rfkill state does.  So we ignore daemon enabled state
	 * when determining what the new state should be since it shouldn't block
	 * the user's request.
	 */
	old_enabled = radio_enabled_for_rstate (rstate, TRUE);
	rstate->user_enabled = enabled;
	new_enabled = radio_enabled_for_rstate (rstate, FALSE);
	if (new_enabled != old_enabled) {
		manager_update_radio_enabled (self, rstate, new_enabled);

		/* For WiFi only (for now) set the actual kernel rfkill state */
		if (rstate->rtype == RFKILL_TYPE_WLAN)
			rfkill_change_wifi (rstate->desc, new_enabled);
	}
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMManager *self = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_NETWORKING_ENABLED:
		/* Construct only for now */
		priv->net_enabled = g_value_get_boolean (value);
		break;
	case PROP_WIRELESS_ENABLED:
		manager_radio_user_toggled (NM_MANAGER (object),
		                            &priv->radio_states[RFKILL_TYPE_WLAN],
		                            g_value_get_boolean (value));
		break;
	case PROP_WWAN_ENABLED:
		manager_radio_user_toggled (NM_MANAGER (object),
		                            &priv->radio_states[RFKILL_TYPE_WWAN],
		                            g_value_get_boolean (value));
		break;
	case PROP_WIMAX_ENABLED:
		manager_radio_user_toggled (NM_MANAGER (object),
		                            &priv->radio_states[RFKILL_TYPE_WIMAX],
		                            g_value_get_boolean (value));
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
	case PROP_VERSION:
		g_value_set_string (value, VERSION);
		break;
	case PROP_STATE:
		nm_manager_update_state (self);
		g_value_set_uint (value, priv->state);
		break;
	case PROP_NETWORKING_ENABLED:
		g_value_set_boolean (value, priv->net_enabled);
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, radio_enabled_for_type (self, RFKILL_TYPE_WLAN, TRUE));
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->radio_states[RFKILL_TYPE_WLAN].hw_enabled);
		break;
	case PROP_WWAN_ENABLED:
		g_value_set_boolean (value, radio_enabled_for_type (self, RFKILL_TYPE_WWAN, TRUE));
		break;
	case PROP_WWAN_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->radio_states[RFKILL_TYPE_WWAN].hw_enabled);
		break;
	case PROP_WIMAX_ENABLED:
		g_value_set_boolean (value, radio_enabled_for_type (self, RFKILL_TYPE_WIMAX, TRUE));
		break;
	case PROP_WIMAX_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->radio_states[RFKILL_TYPE_WIMAX].hw_enabled);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		g_value_take_boxed (value, get_active_connections (self, NULL));
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case PROP_SLEEPING:
		g_value_set_boolean (value, priv->sleeping);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
periodic_update_active_connection_timestamps (gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	GPtrArray *active;
	int i;

	active = get_active_connections (manager, NULL);

	for (i = 0; i < active->len; i++) {
		const char *active_path = g_ptr_array_index (active, i);
		NMActRequest *req;
		NMDevice *device = NULL;

		req = nm_manager_get_act_request_by_path (manager, active_path, &device);
		if (device && nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED)
			nm_settings_connection_update_timestamp (NM_SETTINGS_CONNECTION (nm_act_request_get_connection (req)),
			                                         (guint64) time (NULL));
	}

	return TRUE;
}

static void
authority_changed_cb (gpointer user_data)
{
	/* Let clients know they should re-check their authorization */
	g_signal_emit (NM_MANAGER (user_data), signals[CHECK_PERMISSIONS], 0);
}

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *g_connection;
	guint id, i;
	GFile *file;

	/* Initialize rfkill structures and states */
	memset (priv->radio_states, 0, sizeof (priv->radio_states));

	priv->radio_states[RFKILL_TYPE_WLAN].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WLAN].key = "WirelessEnabled";
	priv->radio_states[RFKILL_TYPE_WLAN].prop = NM_MANAGER_WIRELESS_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].hw_prop = NM_MANAGER_WIRELESS_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].desc = "WiFi";
	priv->radio_states[RFKILL_TYPE_WLAN].other_enabled_func = nm_manager_get_ipw_rfkill_state;
	priv->radio_states[RFKILL_TYPE_WLAN].rtype = RFKILL_TYPE_WLAN;

	priv->radio_states[RFKILL_TYPE_WWAN].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WWAN].key = "WWANEnabled";
	priv->radio_states[RFKILL_TYPE_WWAN].prop = NM_MANAGER_WWAN_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].hw_prop = NM_MANAGER_WWAN_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].desc = "WWAN";
	priv->radio_states[RFKILL_TYPE_WWAN].daemon_enabled_func = nm_manager_get_modem_enabled_state;
	priv->radio_states[RFKILL_TYPE_WWAN].rtype = RFKILL_TYPE_WWAN;

	priv->radio_states[RFKILL_TYPE_WIMAX].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WIMAX].key = "WiMAXEnabled";
	priv->radio_states[RFKILL_TYPE_WIMAX].prop = NM_MANAGER_WIMAX_ENABLED;
	priv->radio_states[RFKILL_TYPE_WIMAX].hw_prop = NM_MANAGER_WIMAX_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WIMAX].desc = "WiMAX";
	priv->radio_states[RFKILL_TYPE_WIMAX].other_enabled_func = NULL;
	priv->radio_states[RFKILL_TYPE_WIMAX].rtype = RFKILL_TYPE_WIMAX;

	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		priv->radio_states[i].hw_enabled = TRUE;

	priv->sleeping = FALSE;
	priv->state = NM_STATE_DISCONNECTED;

	priv->dbus_mgr = nm_dbus_manager_get ();

	priv->modem_manager = nm_modem_manager_get ();
	priv->modem_added_id = g_signal_connect (priv->modem_manager, "modem-added",
	                                         G_CALLBACK (modem_added), manager);
	priv->modem_removed_id = g_signal_connect (priv->modem_manager, "modem-removed",
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
		nm_log_warn (LOGD_AUTOIP4, "could not initialize avahi-autoipd D-Bus proxy");

	/* upower sleep/wake handling */
	priv->upower_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                                UPOWER_DBUS_SERVICE,
	                                                "/org/freedesktop/UPower",
	                                                "org.freedesktop.UPower");
	if (priv->upower_proxy) {
		dbus_g_proxy_add_signal (priv->upower_proxy, "Sleeping", G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (priv->upower_proxy, "Sleeping",
		                             G_CALLBACK (upower_sleeping_cb),
		                             manager, NULL);

		dbus_g_proxy_add_signal (priv->upower_proxy, "Resuming", G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (priv->upower_proxy, "Resuming",
		                             G_CALLBACK (upower_resuming_cb),
		                             manager, NULL);
	} else
		nm_log_warn (LOGD_SUSPEND, "could not initialize UPower D-Bus proxy");

	/* Listen for authorization changes */
	nm_auth_set_changed_func (authority_changed_cb, manager);

	/* Monitor the firmware directory */
	if (strlen (KERNEL_FIRMWARE_DIR)) {
		file = g_file_new_for_path (KERNEL_FIRMWARE_DIR "/");
		priv->fw_monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
		g_object_unref (file);
	}

	if (priv->fw_monitor) {
		priv->fw_monitor_id = g_signal_connect (priv->fw_monitor, "changed",
		                                        G_CALLBACK (firmware_dir_changed),
		                                        manager);
		nm_log_info (LOGD_CORE, "monitoring kernel firmware directory '%s'.",
		             KERNEL_FIRMWARE_DIR);
	} else {
		nm_log_warn (LOGD_CORE, "failed to monitor kernel firmware directory '%s'.",
		             KERNEL_FIRMWARE_DIR);
	}

	/* Update timestamps in active connections */
	priv->timestamp_update_id = g_timeout_add_seconds (300, (GSourceFunc) periodic_update_active_connection_timestamps, manager);
}

static void
nm_manager_class_init (NMManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMManagerPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_VERSION,
		 g_param_spec_string (NM_MANAGER_VERSION,
		                      "Version",
		                      "NetworkManager version",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_MANAGER_STATE,
		                    "State",
		                    "Current state",
		                    0, NM_STATE_DISCONNECTED, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_NETWORKING_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_NETWORKING_ENABLED,
		                       "NetworkingEnabled",
		                       "Is networking enabled",
		                       TRUE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

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
		(object_class, PROP_WWAN_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WWAN_ENABLED,
		                       "WwanEnabled",
		                       "Is mobile broadband enabled",
		                       TRUE,
		                       G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_WWAN_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WWAN_HARDWARE_ENABLED,
		                       "WwanHardwareEnabled",
		                       "Whether WWAN is disabled by a hardware switch or not",
		                       TRUE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_WIMAX_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIMAX_ENABLED,
		                       "WimaxEnabled",
		                       "Is WiMAX enabled",
		                       TRUE,
		                       G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_WIMAX_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIMAX_HARDWARE_ENABLED,
		                       "WimaxHardwareEnabled",
		                       "Whether WiMAX is disabled by a hardware switch or not",
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

	/* Sleeping is not exported over D-Bus */
	g_object_class_install_property
		(object_class, PROP_SLEEPING,
		 g_param_spec_boolean (NM_MANAGER_SLEEPING,
		                       "Sleeping",
		                       "Sleeping",
		                       FALSE,
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

	signals[CHECK_PERMISSIONS] =
		g_signal_new ("check-permissions",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[USER_PERMISSIONS_CHANGED] =
		g_signal_new ("user-permissions-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
	                                 &dbus_glib_nm_manager_object_info);

	dbus_g_error_domain_register (NM_MANAGER_ERROR, NULL, NM_TYPE_MANAGER_ERROR);
	dbus_g_error_domain_register (NM_LOGGING_ERROR, "org.freedesktop.NetworkManager.Logging", NM_TYPE_LOGGING_ERROR);
}

