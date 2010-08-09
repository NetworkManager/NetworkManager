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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include <netinet/ether.h>
#include <string.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>

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
#include "nm-device-cdma.h"
#include "nm-device-gsm.h"
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
#include "nm-sysconfig-settings.h"
#include "nm-secrets-provider-interface.h"
#include "nm-settings-interface.h"
#include "nm-settings-system-interface.h"
#include "nm-manager-auth.h"

#define NM_AUTOIP_DBUS_SERVICE "org.freedesktop.nm_avahi_autoipd"
#define NM_AUTOIP_DBUS_IFACE   "org.freedesktop.nm_avahi_autoipd"

static gboolean impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err);
static void impl_manager_activate_connection (NMManager *manager,
                                              const char *service_name,
                                              const char *connection_path,
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

static gboolean impl_manager_set_logging (NMManager *manager,
                                          const char *level,
                                          const char *domains,
                                          GError **error);

/* Legacy 0.6 compatibility interface */

static void impl_manager_legacy_sleep (NMManager *manager, DBusGMethodInvocation *context);
static void impl_manager_legacy_wake  (NMManager *manager, DBusGMethodInvocation *context);
static gboolean impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err);

#include "nm-manager-glue.h"

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
                                             gboolean assumed,
                                             GError **error);

static NMDevice *find_device_by_iface (NMManager *self, const gchar *iface);

static GSList * remove_one_device (NMManager *manager,
                                   GSList *list,
                                   NMDevice *device,
                                   gboolean quitting,
                                   gboolean force_unmanage);

static NMDevice *nm_manager_get_device_by_udi (NMManager *manager, const char *udi);

#define SSD_POKE_INTERVAL 120
#define ORIGDEV_TAG "originating-device"

typedef struct PendingActivation PendingActivation;
typedef void (*PendingActivationFunc) (PendingActivation *pending,
                                       GError *error);

struct PendingActivation {
	NMManager *manager;

	DBusGMethodInvocation *context;
	PolkitAuthority *authority;
	PendingActivationFunc callback;
	NMAuthChain *chain;

	gboolean have_connection;
	gboolean authorized;

	NMConnectionScope scope;
	char *connection_path;
	char *specific_object_path;
	char *device_path;
	guint timeout_id;
};

typedef struct {
	gboolean enabled;
	gboolean hw_enabled;
	RfKillType rtype;
	const char *desc;
	const char *key;
	const char *prop;
	const char *hw_prop;
	RfKillState (*other_enabled_func) (NMManager *);
} RadioState;

typedef struct {
	char *config_file;
	char *state_file;

	GSList *devices;
	NMState state;

	NMDBusManager *dbus_mgr;
	NMUdevManager *udev_mgr;
	NMBluezManager *bluez_mgr;

	GHashTable *user_connections;
	DBusGProxy *user_proxy;
	NMAuthCallResult user_con_perm;
	NMAuthCallResult user_net_perm;

	GHashTable *system_connections;
	NMSysconfigSettings *sys_settings;
	char *hostname;

	GSList *secrets_calls;

	GSList *pending_activations;

	RadioState radio_states[RFKILL_TYPE_MAX];
	gboolean sleeping;
	gboolean net_enabled;

	NMVPNManager *vpn_manager;
	guint vpn_manager_id;

	NMModemManager *modem_manager;
	guint modem_added_id;
	guint modem_removed_id;

	DBusGProxy *aipd_proxy;

	PolkitAuthority *authority;
	guint auth_changed_id;
	GSList *auth_chains;

	/* Firmware dir monitor */
	GFileMonitor *fw_monitor;
	guint fw_monitor_id;
	guint fw_changed_id;

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
	CHECK_PERMISSIONS,
	USER_PERMISSIONS_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_STATE,
	PROP_NETWORKING_ENABLED,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,
	PROP_WWAN_ENABLED,
	PROP_WWAN_HARDWARE_ENABLED,
	PROP_ACTIVE_CONNECTIONS,

	/* Not exported */
	PROP_HOSTNAME,
	PROP_SLEEPING,

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
	NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED,
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
			/* The manager is already in the requested enabled/disabled state */
			ENUM_ENTRY (NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED, "AlreadyEnabledOrDisabled"),
			{ 0, 0, 0 },
		};
		etype = g_enum_register_static ("NMManagerError", values);
	}
	return etype;
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

	replace_device = find_device_by_iface (NM_MANAGER (user_data), ip_iface);
	if (replace_device) {
		priv->devices = remove_one_device (NM_MANAGER (user_data),
		                                   priv->devices,
		                                   replace_device,
		                                   FALSE,
		                                   TRUE);
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

	/* Otherwise make a new top-level NMDevice for it */
	if (NM_IS_MODEM_GSM (modem))
		device = nm_device_gsm_new (NM_MODEM_GSM (modem), driver);
	else if (NM_IS_MODEM_CDMA (modem))
		device = nm_device_cdma_new (NM_MODEM_CDMA (modem), driver);
	else
		nm_log_info (LOGD_MB, "unhandled modem '%s'", ip_iface);

	if (device)
		add_device (self, device);
}

static void
nm_manager_update_state (NMManager *manager)
{
	NMManagerPrivate *priv;
	NMState new_state = NM_STATE_DISCONNECTED;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (manager_sleeping (manager))
		new_state = NM_STATE_ASLEEP;
	else {
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
remove_one_device (NMManager *manager,
                   GSList *list,
                   NMDevice *device,
                   gboolean quitting,
                   gboolean force_unmanage)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (nm_device_get_managed (device)) {
		gboolean unmanage = !quitting;

		/* Don't unmanage active assume-connection-capable devices at shutdown */
		if (   nm_device_interface_can_assume_connection (NM_DEVICE_INTERFACE (device))
		    && nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED)
			unmanage = FALSE;

		if (unmanage || force_unmanage)
			nm_device_set_managed (device, FALSE, NM_DEVICE_STATE_REASON_REMOVED);
	}

	g_signal_handlers_disconnect_by_func (device, manager_device_state_changed, manager);

	nm_sysconfig_settings_device_removed (priv->sys_settings, device);
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
		priv->devices = remove_one_device (self, priv->devices, found, FALSE, TRUE);
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
nm_manager_pending_activation_remove (NMManager *self,
                                      PendingActivation *pending)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	priv->pending_activations = g_slist_remove (priv->pending_activations, pending);
}

static PendingActivation *
pending_activation_new (NMManager *manager,
                        PolkitAuthority *authority,
                        DBusGMethodInvocation *context,
                        const char *device_path,
                        NMConnectionScope scope,
                        const char *connection_path,
                        const char *specific_object_path,
                        PendingActivationFunc callback)
{
	PendingActivation *pending;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (authority != NULL, NULL);
	g_return_val_if_fail (context != NULL, NULL);
	g_return_val_if_fail (device_path != NULL, NULL);
	g_return_val_if_fail (connection_path != NULL, NULL);

	pending = g_slice_new0 (PendingActivation);
	pending->manager = manager;
	pending->authority = authority;
	pending->context = context;
	pending->callback = callback;

	pending->device_path = g_strdup (device_path);
	pending->scope = scope;
	pending->connection_path = g_strdup (connection_path);

	/* "/" is special-cased to NULL to get through D-Bus */
	if (specific_object_path && strcmp (specific_object_path, "/"))
		pending->specific_object_path = g_strdup (specific_object_path);

	return pending;
}

static void
pending_auth_user_done (NMAuthChain *chain,
                        GError *error,
                        DBusGMethodInvocation *context,
                        gpointer user_data)
{
	PendingActivation *pending = user_data;
	NMAuthCallResult result;

	pending->chain = NULL;

	if (error) {
		pending->callback (pending, error);
		goto out;
	}

	/* Caller has had a chance to obtain authorization, so we only need to
	 * check for 'yes' here.
	 */
	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS));
	if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Not authorized to use user connections.");
		pending->callback (pending, error);
		g_error_free (error);
	} else
		pending->callback (pending, NULL);

out:
	nm_auth_chain_unref (chain);
}

static void
pending_auth_net_done (NMAuthChain *chain,
                       GError *error,
                       DBusGMethodInvocation *context,
                       gpointer user_data)
{
	PendingActivation *pending = user_data;
	NMAuthCallResult result;

	pending->chain = NULL;

	if (error) {
		pending->callback (pending, error);
		goto out;
	}

	/* Caller has had a chance to obtain authorization, so we only need to
	 * check for 'yes' here.
	 */
	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL));
	if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Not authorized to control networking.");
		pending->callback (pending, error);
		g_error_free (error);
		goto out;
	}

	if (pending->scope == NM_CONNECTION_SCOPE_SYSTEM) {
		/* System connection and the user is authorized for that if they have
		 * the network-control permission.
		 */
		pending->callback (pending, NULL);
	} else {
		g_assert (pending->scope == NM_CONNECTION_SCOPE_USER);

		/* User connection, check the 'use-user-connections' permission */
		pending->chain = nm_auth_chain_new (pending->authority,
			                                pending->context,
			                                NULL,
			                                pending_auth_user_done,
			                                pending);
		nm_auth_chain_add_call (pending->chain,
			                    NM_AUTH_PERMISSION_USE_USER_CONNECTIONS,
			                    TRUE);
	}

out:
	nm_auth_chain_unref (chain);
}

static gboolean
check_user_authorized (NMDBusManager *dbus_mgr,
                       DBusGProxy *user_proxy,
                       DBusGMethodInvocation *context,
                       NMConnectionScope scope,
                       gulong *out_sender_uid,
                       const char **out_error_desc)
{
	g_return_val_if_fail (dbus_mgr != NULL, FALSE);
	g_return_val_if_fail (context != NULL, FALSE);
	g_return_val_if_fail (out_sender_uid != NULL, FALSE);
	g_return_val_if_fail (out_error_desc != NULL, FALSE);

	*out_sender_uid = G_MAXULONG;

	/* Get the UID */
	if (!nm_auth_get_caller_uid (context, dbus_mgr, out_sender_uid, out_error_desc))
		return FALSE;

	/* root gets to do anything */
	if (0 == *out_sender_uid)
		return TRUE;

	/* Check whether the UID is authorized for user connections */
	if (   scope == NM_CONNECTION_SCOPE_USER
	    && !nm_auth_uid_authorized (*out_sender_uid,
	                                dbus_mgr,
	                                user_proxy,
	                                out_error_desc))
		return FALSE;

	return TRUE;
}

static void
pending_activation_check_authorized (PendingActivation *pending,
                                     NMDBusManager *dbus_mgr,
                                     DBusGProxy *user_proxy)
{
	const char *error_desc = NULL;
	gulong sender_uid = G_MAXULONG;
	GError *error;

	g_return_if_fail (pending != NULL);
	g_return_if_fail (dbus_mgr != NULL);

	if (!check_user_authorized (dbus_mgr,
	                            user_proxy,
	                            pending->context,
	                            pending->scope,
	                            &sender_uid,
	                            &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		pending->callback (pending, error);
		g_error_free (error);
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
	pending->chain = nm_auth_chain_new (pending->authority,
	                                    pending->context,
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

	if (pending->timeout_id)
		g_source_remove (pending->timeout_id);
	g_free (pending->connection_path);
	g_free (pending->specific_object_path);
	g_free (pending->device_path);

	if (error)
		dbus_g_method_return_error (pending->context, error);
	else if (ac_path)
		dbus_g_method_return (pending->context, ac_path);

	if (pending->chain)
		nm_auth_chain_unref (pending->chain);

	memset (pending, 0, sizeof (PendingActivation));
	g_slice_free (PendingActivation, pending);
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
user_proxy_cleanup (NMManager *self, gboolean resync_bt)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->user_connections) {
		g_hash_table_foreach (priv->user_connections, emit_removed, self);
		g_hash_table_remove_all (priv->user_connections);
	}

	priv->user_net_perm = NM_AUTH_CALL_RESULT_UNKNOWN;
	priv->user_con_perm = NM_AUTH_CALL_RESULT_UNKNOWN;

	if (priv->user_proxy) {
		g_object_unref (priv->user_proxy);
		priv->user_proxy = NULL;
	}

	if (resync_bt) {
		/* Resync BT devices since they are generated from connections */
		bluez_manager_resync_devices (self);
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
		nm_log_info (LOGD_USER_SET, "couldn't retrieve connection settings: %s.",
		             err && err->message ? err->message : "(unknown)");
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
			nm_log_warn (LOGD_USER_SET, "invalid connection: '%s' / '%s' invalid: %d",
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
		nm_log_dbg (LOGD_USER_SET, "implement merge settings");
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
		nm_log_warn (LOGD_USER_SET, "invalid connection: '%s' / '%s' invalid: %d",
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
		nm_log_err (LOGD_USER_SET, "could not init user connection proxy");
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
		nm_log_warn (LOGD_USER_SET, "couldn't retrieve connections: %s",
		             err && err->message ? err->message : "(unknown)");
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
user_proxy_destroyed_cb (DBusGProxy *proxy, NMManager *self)
{
	nm_log_dbg (LOGD_USER_SET, "Removing user connections...");

	/* At this point the user proxy is already being disposed */
	NM_MANAGER_GET_PRIVATE (self)->user_proxy = NULL;

	/* User Settings service disappeared; throw away user connections */
	user_proxy_cleanup (self, TRUE);
}

static void
user_new_connection_cb (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	user_internal_new_connection_cb (proxy, path, NM_MANAGER (user_data), NULL);
}

static gboolean
user_settings_authorized (NMManager *self, NMAuthChain *chain)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMAuthCallResult old_net_perm = priv->user_net_perm;
	NMAuthCallResult old_con_perm = priv->user_con_perm;

	/* If the user could potentially get authorization to use networking and/or
	 * to use user connections, the user settings service is authorized.
	 */
	priv->user_net_perm = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL));
	priv->user_con_perm = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS));

	nm_log_dbg (LOGD_USER_SET, "User connections permissions: net %d, con %d",
	            priv->user_net_perm, priv->user_con_perm);

	if (old_net_perm != priv->user_net_perm || old_con_perm != priv->user_con_perm)
		g_signal_emit (self, signals[USER_PERMISSIONS_CHANGED], 0);

	/* If the user can't control the network they certainly aren't allowed
	 * to provide user connections.
	 */
	if (   priv->user_net_perm == NM_AUTH_CALL_RESULT_UNKNOWN
	    || priv->user_net_perm == NM_AUTH_CALL_RESULT_NO)
		return FALSE;

	/* And of course if they aren't allowed to use user connections, they can't
	 * provide them either.
	 */
	if (   priv->user_con_perm == NM_AUTH_CALL_RESULT_UNKNOWN
	    || priv->user_con_perm == NM_AUTH_CALL_RESULT_NO)
		return FALSE;

	return TRUE;
}

static void
user_proxy_auth_done (NMAuthChain *chain,
                      GError *error,
                      DBusGMethodInvocation *context,
                      gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean authorized = FALSE;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	if (error) {
		nm_log_warn (LOGD_USER_SET, "User connections unavailable: (%d) %s",
		             error->code, error->message ? error->message : "(unknown)");
	} else
		authorized = user_settings_authorized (self, chain);

	if (authorized) {
		/* If authorized, finish setting up the user settings service proxy */
		nm_log_dbg (LOGD_USER_SET, "Requesting user connections...");

		authorized = TRUE;

		dbus_g_proxy_add_signal (priv->user_proxy,
			                     "NewConnection",
			                     DBUS_TYPE_G_OBJECT_PATH,
			                     G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (priv->user_proxy, "NewConnection",
			                         G_CALLBACK (user_new_connection_cb),
			                         self,
			                         NULL);

		/* Clean up when the user settings proxy goes away */
		g_signal_connect (priv->user_proxy, "destroy",
			              G_CALLBACK (user_proxy_destroyed_cb),
			              self);

		/* Request user connections */
		dbus_g_proxy_begin_call (priv->user_proxy, "ListConnections",
			                     user_list_connections_cb,
			                     self,
			                     NULL,
			                     G_TYPE_INVALID);
	} else {
		/* Otherwise, we ignore the user settings service completely */
		user_proxy_cleanup (self, TRUE);
	}

	nm_auth_chain_unref (chain);
}

static void
user_proxy_init (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	DBusGConnection *bus;
	NMAuthChain *chain;
	GError *error = NULL;

	g_return_if_fail (self != NULL);
	g_return_if_fail (priv->user_proxy == NULL);

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->user_proxy = dbus_g_proxy_new_for_name_owner (bus,
	                                                    NM_DBUS_SERVICE_USER_SETTINGS,
	                                                    NM_DBUS_PATH_SETTINGS,
	                                                    NM_DBUS_IFACE_SETTINGS,
	                                                    &error);
	if (!priv->user_proxy) {
		nm_log_err (LOGD_USER_SET, "could not init user settings proxy: (%d) %s",
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	/* Kick off some PolicyKit authorization requests to figure out what
	 * permissions this user settings service has.
	 */
	chain = nm_auth_chain_new (priv->authority,
	                           NULL,
	                           priv->user_proxy,
	                           user_proxy_auth_done,
	                           self);
	priv->auth_chains = g_slist_prepend (priv->auth_chains, chain);

	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, FALSE);
}

/*******************************************************************/
/* System settings stuff via NMSysconfigSettings                   */
/*******************************************************************/

static void
system_connection_updated_cb (NMSettingsConnectionInterface *connection,
                              gpointer unused,
                              NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const char *path;
	NMSettingsConnectionInterface *existing;
	GError *error = NULL;

	path = nm_connection_get_path (NM_CONNECTION (connection));

	existing = g_hash_table_lookup (priv->system_connections, path);
	if (!existing)
		return;
	if (existing != connection) {
		nm_log_warn (LOGD_SYS_SET, "existing connection didn't matched updated.");
		return;
	}

	if (!nm_connection_verify (NM_CONNECTION (existing), &error)) {
		/* Updated connection invalid, remove existing connection */
		nm_log_warn (LOGD_SYS_SET, "invalid connection: '%s' / '%s' invalid: %d",
		             g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
		             error->message, error->code);
		g_error_free (error);
		remove_connection (manager, NM_CONNECTION (existing), priv->system_connections);
		return;
	}

	g_signal_emit (manager, signals[CONNECTION_UPDATED], 0,
	               existing, NM_CONNECTION_SCOPE_SYSTEM);

	bluez_manager_resync_devices (manager);
}

static void
system_connection_removed_cb (NMSettingsConnectionInterface *connection,
                              NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const char *path;

	path = nm_connection_get_path (NM_CONNECTION (connection));

	connection = g_hash_table_lookup (priv->system_connections, path);
	if (connection)
		remove_connection (manager, NM_CONNECTION (connection), priv->system_connections);
}

static void
system_internal_new_connection (NMManager *manager,
                                NMSettingsConnectionInterface *connection)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const char *path;

	g_return_if_fail (connection != NULL);

	g_signal_connect (connection, NM_SETTINGS_CONNECTION_INTERFACE_UPDATED,
	                  G_CALLBACK (system_connection_updated_cb), manager);
	g_signal_connect (connection, NM_SETTINGS_CONNECTION_INTERFACE_REMOVED,
	                  G_CALLBACK (system_connection_removed_cb), manager);

	path = nm_connection_get_path (NM_CONNECTION (connection));
	g_hash_table_insert (priv->system_connections, g_strdup (path),
	                     g_object_ref (connection));
	g_signal_emit (manager, signals[CONNECTION_ADDED], 0, connection, NM_CONNECTION_SCOPE_SYSTEM);
}

static void
system_new_connection_cb (NMSysconfigSettings *settings,
                          NMSettingsConnectionInterface *connection,
                          NMManager *manager)
{
	system_internal_new_connection (manager, connection);
}

static void
system_query_connections (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *system_connections, *iter;

	system_connections = nm_settings_interface_list_connections (NM_SETTINGS_INTERFACE (priv->sys_settings));
	for (iter = system_connections; iter; iter = g_slist_next (iter))
		system_internal_new_connection (manager, NM_SETTINGS_CONNECTION_INTERFACE (iter->data));
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
		if (!old_owner_good && new_owner_good)
			user_proxy_init (manager);
		else
			user_proxy_cleanup (manager, TRUE);
	}
}

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

static void
manager_set_radio_enabled (NMManager *manager,
                           RadioState *rstate,
                           gboolean enabled)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;
	GError *error = NULL;

	/* Do nothing for radio types not yet implemented */
	if (!rstate->prop)
		return;

	if (rstate->enabled == enabled)
		return;

	/* Can't set wireless enabled if it's disabled in hardware */
	if (!rstate->hw_enabled && enabled)
		return;

	rstate->enabled = enabled;

	g_object_notify (G_OBJECT (manager), rstate->prop);

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
		}
	}

	/* Don't touch devices if asleep/networking disabled */
	if (manager_sleeping (manager))
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
manager_rfkill_update_one_type (NMManager *self,
                                RadioState *rstate,
                                RfKillType rtype)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	RfKillState udev_state = RFKILL_UNBLOCKED;
	RfKillState other_state = RFKILL_UNBLOCKED;
	RfKillState composite;
	gboolean new_e = TRUE, new_he = TRUE;

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

	switch (composite) {
	case RFKILL_UNBLOCKED:
		new_e = TRUE;
		new_he = TRUE;
		break;
	case RFKILL_SOFT_BLOCKED:
		new_e = FALSE;
		new_he = TRUE;
		break;
	case RFKILL_HARD_BLOCKED:
		new_e = FALSE;
		new_he = FALSE;
		break;
	default:
		break;
	}

	if (rstate->desc) {
		nm_log_dbg (LOGD_RFKILL, "%s hw-enabled %d enabled %d",
		            rstate->desc, new_he, new_e);
	}

	if (new_he != rstate->hw_enabled) {
		nm_log_info (LOGD_RFKILL, "%s now %s by radio killswitch",
		             rstate->desc,
		             (new_e && new_he) ? "enabled" : "disabled");

		rstate->hw_enabled = new_he;
		if (rstate->hw_prop)
			g_object_notify (G_OBJECT (self), rstate->hw_prop);
	}
	manager_set_radio_enabled (self, rstate, new_e);
}

static void
nm_manager_rfkill_update (NMManager *self, RfKillType rtype)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	guint i;

	if (rtype != RFKILL_TYPE_UNKNOWN) {
		manager_rfkill_update_one_type (self, &priv->radio_states[rtype], rtype);
		return;
	}

	/* Otherwise sync all radio types */
	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		manager_rfkill_update_one_type (self, &priv->radio_states[i], i);
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
		                    "Not authorized to %s user connections",
		                    detail);
	}
	return NULL;
}

static void
disconnect_user_auth_done_cb (NMAuthChain *chain,
                              GError *error,
                              DBusGMethodInvocation *context,
                              gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error = NULL;
	NMAuthCallResult result;
	NMDevice *device;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS));
	ret_error = deactivate_disconnect_check_error (error, result, "Disconnect");
	if (!ret_error) {
		/* Everything authorized, deactivate the connection */
		device = nm_auth_chain_get_data (chain, "device");
		if (nm_device_interface_disconnect (NM_DEVICE_INTERFACE (device), &ret_error))
			dbus_g_method_return (context);
	}

	if (ret_error)
		dbus_g_method_return_error (context, ret_error);
	g_clear_error (&ret_error);

	nm_auth_chain_unref (chain);
}

static void
disconnect_net_auth_done_cb (NMAuthChain *chain,
                             GError *error,
                             DBusGMethodInvocation *context,
                             gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error = NULL;
	NMAuthCallResult result;
	NMConnectionScope scope;
	NMDevice *device;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL));
	ret_error = deactivate_disconnect_check_error (error, result, "Disconnect");
	if (ret_error) {
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
		goto done;
	}

	/* If it's a system connection, we're done */
	device = nm_auth_chain_get_data (chain, "device");
	scope = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "scope"));
	if (scope == NM_CONNECTION_SCOPE_USER) {
		NMAuthChain *user_chain;

		/* It's a user connection, so we need to ensure the caller is
		 * authorized to manipulate user connections.
		 */
		user_chain = nm_auth_chain_new (priv->authority, context, NULL, disconnect_user_auth_done_cb, self);
		g_assert (user_chain);
		priv->auth_chains = g_slist_append (priv->auth_chains, user_chain);

		nm_auth_chain_set_data (user_chain, "device", g_object_ref (device), g_object_unref);
		nm_auth_chain_set_data (user_chain, "scope", GUINT_TO_POINTER (scope), NULL);
		nm_auth_chain_add_call (user_chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS, TRUE);
	} else {
		if (!nm_device_interface_disconnect (NM_DEVICE_INTERFACE (device), &ret_error)) {
			dbus_g_method_return_error (context, ret_error);
			g_clear_error (&ret_error);
		} else
			dbus_g_method_return (context);
	}

done:
	nm_auth_chain_unref (chain);
}

static void
manager_device_disconnect_request (NMDevice *device,
                                   DBusGMethodInvocation *context,
                                   NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActRequest *req;
	NMConnection *connection;
	GError *error = NULL;
	NMConnectionScope scope;
	gulong sender_uid = G_MAXULONG;
	const char *error_desc = NULL;

	req = nm_device_get_act_request (device);
	if (!req) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "This device is not active");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	/* Need to check the caller's permissions and stuff before we can
	 * deactivate the connection.
	 */
	scope = nm_connection_get_scope (connection);
	if (!check_user_authorized (priv->dbus_mgr,
	                            priv->user_proxy,
	                            context,
	                            scope,
	                            &sender_uid,
	                            &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
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
		chain = nm_auth_chain_new (priv->authority, context, NULL, disconnect_net_auth_done_cb, self);
		g_assert (chain);
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);

		nm_auth_chain_set_data (chain, "device", g_object_ref (device), g_object_unref);
		nm_auth_chain_set_data (chain, "scope", GUINT_TO_POINTER (scope), NULL);
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
	GHashTableIter iter;
	gpointer value;
	gboolean managed = FALSE;

	iface = nm_device_get_ip_iface (device);
	g_assert (iface);

	if (!NM_IS_DEVICE_MODEM (device) && find_device_by_iface (self, iface)) {
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

		/* Update global rfkill state with this device's rfkill state, and
		 * then set this device's rfkill state based on the global state.
		 */
		nm_manager_rfkill_update (self, RFKILL_TYPE_WLAN);
		nm_device_interface_set_enabled (NM_DEVICE_INTERFACE (device),
		                                 priv->radio_states[RFKILL_TYPE_WLAN].enabled);
	} else if (NM_IS_DEVICE_MODEM (device)) {
		g_signal_connect (device, NM_DEVICE_MODEM_ENABLE_CHANGED,
		                  G_CALLBACK (manager_modem_enabled_changed),
		                  self);

		nm_manager_rfkill_update (self, RFKILL_TYPE_WWAN);
		/* Until we start respecting WWAN rfkill switches the modem itself
		 * is the source of the enabled/disabled state, so the manager shouldn't
		 * touch it here.
		nm_device_interface_set_enabled (NM_DEVICE_INTERFACE (device),
		                                 priv->radio_states[RFKILL_TYPE_WWAN].enabled);
		*/
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
	if (nm_device_interface_can_assume_connection (NM_DEVICE_INTERFACE (device))) {
		GSList *connections = NULL;

		g_hash_table_iter_init (&iter, priv->system_connections);
		while (g_hash_table_iter_next (&iter, NULL, &value))
			connections = g_slist_append (connections, value);
		existing = nm_device_interface_connection_match_config (NM_DEVICE_INTERFACE (device),
		                                                        (const GSList *) connections);
		g_slist_free (connections);

		if (existing) {
			NMSettingConnection *s_con;

			s_con = (NMSettingConnection *) nm_connection_get_setting (existing, NM_TYPE_SETTING_CONNECTION);
			nm_log_dbg (LOGD_DEVICE, "(%s): found existing device connection '%s'",
			            nm_device_get_iface (device),
			            nm_setting_connection_get_id (s_con));
		}
	}

	/* Start the device if it's supposed to be managed */
	unmanaged_specs = nm_sysconfig_settings_get_unmanaged_specs (priv->sys_settings);
	if (   !manager_sleeping (self)
	    && !nm_device_interface_spec_match_list (NM_DEVICE_INTERFACE (device), unmanaged_specs)) {
		nm_device_set_managed (device,
		                       TRUE,
		                       existing ? NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED :
		                                  NM_DEVICE_STATE_REASON_NOW_MANAGED);
		managed = TRUE;
	}

	nm_sysconfig_settings_device_added (priv->sys_settings, device);
	g_signal_emit (self, signals[DEVICE_ADDED], 0, device);

	/* If the device has a connection it can assume, do that now */
	if (existing && managed && nm_device_is_available (device)) {
		const char *ac_path;
		GError *error = NULL;

		nm_log_dbg (LOGD_DEVICE, "(%s): will attempt to assume existing connection",
		            nm_device_get_iface (device));

		ac_path = internal_activate_device (self, device, existing, NULL, FALSE, TRUE, &error);
		if (ac_path)
			g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
		else {
			nm_log_warn (LOGD_DEVICE, "assumed connection (%d) %s failed to activate: (%d) %s",
			             nm_connection_get_scope (existing),
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
			gone = remove_one_device (self, gone, NM_DEVICE (gone->data), FALSE, TRUE);
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
			priv->devices = remove_one_device (self, priv->devices, device, FALSE, TRUE);
			break;
		}
	}
}

static NMDevice *
find_device_by_iface (NMManager *self, const gchar *iface)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);
		const gchar *d_iface = nm_device_get_ip_iface (device);
		if (!strcmp (d_iface, iface))
			return device;
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
	if (device)
		priv->devices = remove_one_device (self, priv->devices, device, FALSE, TRUE);
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
	GHashTable *settings = NULL;
	GError *error = NULL;
	GObject *provider;

	g_return_if_fail (info != NULL);
	g_return_if_fail (info->provider);
	g_return_if_fail (info->setting_name);

	provider = g_object_ref (info->provider);

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

	g_object_unref (provider);
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
		nm_log_warn (LOGD_USER_SET, "could not create user connection secrets proxy");
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

static void
system_get_secrets_reply_cb (NMSettingsConnectionInterface *connection,
                             GHashTable *secrets,
                             GError *error,
                             gpointer user_data)
{
	GetSecretsInfo *info = user_data;
	GObject *provider;

	provider = g_object_ref (info->provider);

	nm_secrets_provider_interface_get_secrets_result (info->provider,
	                                                  info->setting_name,
	                                                  info->caller,
	                                                  error ? NULL : secrets,
	                                                  error);
	free_get_secrets_info (info);
	g_object_unref (provider);
}

static gboolean
system_get_secrets_idle_cb (gpointer user_data)
{
	GetSecretsInfo *info = user_data;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (info->manager);
	NMSettingsConnectionInterface *connection;
	GError *error = NULL;
	const char *hints[3] = { NULL, NULL, NULL };

	info->idle_id = 0;

	connection = nm_settings_interface_get_connection_by_path (NM_SETTINGS_INTERFACE (priv->sys_settings), 
	                                                           info->connection_path);
	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "unknown connection (not exported by system settings)");
		nm_secrets_provider_interface_get_secrets_result (info->provider,
		                                                  info->setting_name,
		                                                  info->caller,
		                                                  NULL,
		                                                  error);
		g_error_free (error);
		free_get_secrets_info (info);
		return FALSE;
	}

	hints[0] = info->hint1;
	hints[1] = info->hint2;
	nm_settings_connection_interface_get_secrets (connection,
	                                              info->setting_name,
	                                              hints,
	                                              info->request_new,
	                                              system_get_secrets_reply_cb,
	                                              info);
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
	                                 system_get_secrets_idle_cb,
	                                 info,
	                                 NULL);
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

	req = nm_act_request_new (connection, specific_object, user_requested, assumed, (gpointer) device);
	g_signal_connect (req, "manager-get-secrets", G_CALLBACK (provider_get_secrets), manager);
	g_signal_connect (req, "manager-cancel-secrets", G_CALLBACK (provider_cancel_secrets), manager);
	success = nm_device_interface_activate (dev_iface, req, error);
	g_object_unref (req);

	return success ? nm_act_request_get_active_connection_path (req) : NULL;
}

static gboolean
wait_for_connection_expired (gpointer data)
{
	PendingActivation *pending = data;
	GError *error = NULL;

	g_return_val_if_fail (pending != NULL, FALSE);

	nm_log_warn (LOGD_CORE, "connection %s (scope %d) failed to activate (timeout)",
	             pending->connection_path, pending->scope);

	nm_manager_pending_activation_remove (pending->manager, pending);

	error = g_error_new_literal (NM_MANAGER_ERROR,
	                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
	                             "Connection was not provided by any settings service");
	pending_activation_destroy (pending, error, NULL);
	g_error_free (error);
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
	NMManagerPrivate *priv;
	NMDevice *device = NULL;
	NMSettingConnection *s_con;
	NMVPNConnection *vpn_connection;
	const char *path;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (!strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_VPN_SETTING_NAME)) {
		NMActRequest *req = NULL;
		NMVPNManager *vpn_manager;

		/* VPN connection */

		if (specific_object) {
			/* Find the specifc connection the client requested we use */
			req = nm_manager_get_act_request_by_path (manager, specific_object, &device);
			if (!req) {
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
					req = candidate_req;
					break;
				}
			}
		}

		if (!device || !req) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "%s", "Could not find source connection, or the source connection had no active device.");
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
		                                 FALSE,
		                                 error);
	}

	return path;
}

static PendingActivation *
nm_manager_pending_activation_find (NMManager *self,
                                    const char *path,
                                    NMConnectionScope scope)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->pending_activations; iter; iter = g_slist_next (iter)) {
		PendingActivation *pending = iter->data;

		if (!strcmp (pending->connection_path, path) && (pending->scope == scope))
			return pending;
	}
	return NULL;
}

static void
check_pending_ready (NMManager *self, PendingActivation *pending)
{
	NMConnection *connection;
	const char *path = NULL;
	GError *error = NULL;

	if (!pending->have_connection || !pending->authorized)
		return;

	/* Ok, we're authorized and the connection is available */

	nm_manager_pending_activation_remove (self, pending);

	connection = nm_manager_get_connection_by_object_path (self,
	                                                       pending->scope,
	                                                       pending->connection_path);
	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "Connection could not be found.");
		goto out;
	}

	path = nm_manager_activate_connection (self,
	                                       connection,
	                                       pending->specific_object_path,
	                                       pending->device_path,
	                                       TRUE,
	                                       &error);
	if (!path) {
		nm_log_warn (LOGD_CORE, "connection (%d) %s failed to activate: (%d) %s",
		             pending->scope, pending->connection_path, error->code, error->message);
	} else
		g_object_notify (G_OBJECT (pending->manager), NM_MANAGER_ACTIVE_CONNECTIONS);

out:
	pending_activation_destroy (pending, error, path);
	g_clear_error (&error);
}

static void
connection_added_default_handler (NMManager *self,
                                  NMConnection *connection,
                                  NMConnectionScope scope)
{
	PendingActivation *pending;

	pending = nm_manager_pending_activation_find (self,
	                                              nm_connection_get_path (connection),
	                                              scope);
	if (pending) {
		pending->have_connection = TRUE;
		check_pending_ready (self, pending);
	}
}

static void
activation_auth_done (PendingActivation *pending, GError *error)
{
	if (error) {
		nm_manager_pending_activation_remove (pending->manager, pending);
		pending_activation_destroy (pending, error, NULL);
		return;
	} else {
		pending->authorized = TRUE;

		/* Now that we're authorized, if the connection hasn't shown up yet,
		 * start a timer and wait for it.
		 */
		if (!pending->have_connection && !pending->timeout_id)
			pending->timeout_id = g_timeout_add_seconds (5, wait_for_connection_expired, pending);

		check_pending_ready (pending->manager, pending);
	}
}

static void
impl_manager_activate_connection (NMManager *self,
                                  const char *service_name,
                                  const char *connection_path,
                                  const char *device_path,
                                  const char *specific_object_path,
                                  DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMConnectionScope scope = NM_CONNECTION_SCOPE_UNKNOWN;
	PendingActivation *pending;
	GError *error = NULL;

	if (!strcmp (service_name, NM_DBUS_SERVICE_USER_SETTINGS))
		scope = NM_CONNECTION_SCOPE_USER;
	else if (!strcmp (service_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		scope = NM_CONNECTION_SCOPE_SYSTEM;
	else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_INVALID_SERVICE,
		                             "Invalid settings service name");
		dbus_g_method_return_error (context, error);
		nm_log_warn (LOGD_CORE, "connection (%d) %s failed to activate: (%d) %s",
		             scope, connection_path, error->code, error->message);
		g_error_free (error);
		return;
	}

	/* Need to check the caller's permissions and stuff before we can
	 * activate the connection.
	 */
	pending = pending_activation_new (self,
	                                  priv->authority,
	                                  context,
	                                  device_path,
	                                  scope,
	                                  connection_path,
	                                  specific_object_path,
	                                  activation_auth_done);
	priv->pending_activations = g_slist_prepend (priv->pending_activations, pending);

	if (nm_manager_get_connection_by_object_path (self, scope, connection_path))
		pending->have_connection = TRUE;

	pending_activation_check_authorized (pending, priv->dbus_mgr, priv->user_proxy);
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

static void
deactivate_user_auth_done_cb (NMAuthChain *chain,
                              GError *error,
                              DBusGMethodInvocation *context,
                              gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error = NULL;
	NMAuthCallResult result;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS));
	ret_error = deactivate_disconnect_check_error (error, result, "Deactivate");
	if (!ret_error) {
		/* Everything authorized, deactivate the connection */
		if (nm_manager_deactivate_connection (self,
		                                      nm_auth_chain_get_data (chain, "path"),
		                                      NM_DEVICE_STATE_REASON_USER_REQUESTED,
		                                      &ret_error))
			dbus_g_method_return (context);
	}

	if (ret_error)
		dbus_g_method_return_error (context, ret_error);
	g_clear_error (&ret_error);

	nm_auth_chain_unref (chain);
}

static void
deactivate_net_auth_done_cb (NMAuthChain *chain,
                             GError *error,
                             DBusGMethodInvocation *context,
                             gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error = NULL;
	NMAuthCallResult result;
	const char *active_path;
	NMConnectionScope scope;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL));
	ret_error = deactivate_disconnect_check_error (error, result, "Deactivate");
	if (ret_error) {
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
		goto done;
	}

	/* If it's a system connection, we're done */
	active_path = nm_auth_chain_get_data (chain, "path");
	scope = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "scope"));
	if (scope == NM_CONNECTION_SCOPE_USER) {
		NMAuthChain *user_chain;

		/* It's a user connection, so we need to ensure the caller is
		 * authorized to manipulate user connections.
		 */
		user_chain = nm_auth_chain_new (priv->authority, context, NULL, deactivate_user_auth_done_cb, self);
		g_assert (user_chain);
		priv->auth_chains = g_slist_append (priv->auth_chains, user_chain);

		nm_auth_chain_set_data (user_chain, "path", g_strdup (active_path), g_free);
		nm_auth_chain_set_data (user_chain, "scope", GUINT_TO_POINTER (scope), NULL);
		nm_auth_chain_add_call (user_chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS, TRUE);
	} else {
		if (!nm_manager_deactivate_connection (self,
		                                       active_path,
		                                       NM_DEVICE_STATE_REASON_USER_REQUESTED,
		                                       &ret_error)) {
			dbus_g_method_return_error (context, ret_error);
			g_clear_error (&ret_error);
		} else
			dbus_g_method_return (context);
	}

done:
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
	NMConnectionScope scope;
	const char *error_desc = NULL;

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
	scope = nm_connection_get_scope (connection);
	if (!check_user_authorized (priv->dbus_mgr,
	                            priv->user_proxy,
	                            context,
	                            scope,
	                            &sender_uid,
	                            &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
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
	chain = nm_auth_chain_new (priv->authority, context, NULL, deactivate_net_auth_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_set_data (chain, "path", g_strdup (active_path), g_free);
	nm_auth_chain_set_data (chain, "scope", GUINT_TO_POINTER (scope), NULL);
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

		unmanaged_specs = nm_sysconfig_settings_get_unmanaged_specs (priv->sys_settings);

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
				gboolean enabled = (rstate->hw_enabled && rstate->enabled);
				RfKillType devtype = RFKILL_TYPE_UNKNOWN;

				if (rstate->desc) {
					nm_log_dbg (LOGD_RFKILL, "%s %s devices (hw_enabled %d, enabled %d)",
					            enabled ? "enabling" : "disabling",
					            rstate->desc, rstate->hw_enabled, rstate->enabled);
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

static gboolean
return_no_pk_error (PolkitAuthority *authority,
                    const char *detail,
                    DBusGMethodInvocation *context)
{
	GError *error;

	if (!authority) {
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "%s request failed: PolicyKit not initialized",
		                     detail);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return FALSE;
	}
	return TRUE;
}

static void
_internal_sleep (NMManager *self, gboolean do_sleep)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	nm_log_info (LOGD_SUSPEND, "%s requested (sleeping: %s  enabled: %s)",
	             do_sleep ? "sleep" : "wake",
	             priv->sleeping ? "yes" : "no",
	             priv->net_enabled ? "yes" : "no");

	priv->sleeping = do_sleep;

	do_sleep_wake (self);

	g_object_notify (G_OBJECT (self), NM_MANAGER_SLEEPING);
}

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
		nm_log_dbg (LOGD_CORE, "Sleep/wake request failed: %s", error->message);
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

static void
impl_manager_sleep (NMManager *self,
                    gboolean do_sleep,
                    DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv;
	NMAuthChain *chain;
	GError *error = NULL;
	gulong sender_uid = G_MAXULONG;
	const char *error_desc = NULL;

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

	if (!return_no_pk_error (priv->authority, "Sleep/wake", context))
		return;

	chain = nm_auth_chain_new (priv->authority, context, NULL, sleep_auth_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_set_data (chain, "sleep", GUINT_TO_POINTER (do_sleep), NULL);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SLEEP_WAKE, TRUE);
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
	const char *error_desc = NULL;

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
		return;
	}

	/* Root doesn't need PK authentication */
	if (0 == sender_uid) {
		_internal_enable (self, enable);
		dbus_g_method_return (context);
		return;
	}

	if (!return_no_pk_error (priv->authority, "Enable/disable", context))
		return;

	chain = nm_auth_chain_new (priv->authority, context, NULL, enable_net_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_set_data (chain, "enable", GUINT_TO_POINTER (enable), NULL);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK, TRUE);
}

/* Permissions */

static void
user_proxy_permissions_changed_done (NMAuthChain *chain,
                                     GError *error,
                                     DBusGMethodInvocation *context,
                                     gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean authorized = FALSE;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	if (error) {
		nm_log_warn (LOGD_USER_SET, "User connections unavailable: (%d) %s",
		             error->code, error->message ? error->message : "(unknown)");
	} else
		authorized = user_settings_authorized (self, chain);

	if (authorized) {
		/* User connections are authorized */
		if (!priv->user_proxy)
			user_proxy_init (self);
	} else
		user_proxy_cleanup (self, TRUE);

	nm_auth_chain_unref (chain);
}

static void
pk_authority_changed_cb (GObject *object, gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMAuthChain *chain;

	/* If the user settings service wasn't previously authorized, we wouldn't
	 * care about it.  But it might be authorized now, so lets check.
	 */
	if (!priv->user_proxy)
		user_proxy_init (self);
	else {
		/* Otherwise the user settings permissions could have changed so we
		 * need to recheck them.
		 */
		chain = nm_auth_chain_new (priv->authority,
		                           NULL,
		                           priv->user_proxy,
		                           user_proxy_permissions_changed_done,
		                           self);
		priv->auth_chains = g_slist_prepend (priv->auth_chains, chain);

		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS, FALSE);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, FALSE);
	}

	/* Let clients know they should re-check their authorization */
	g_signal_emit (NM_MANAGER (user_data), signals[CHECK_PERMISSIONS], 0);
}

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
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS);
		get_perm_add_result (chain, results, NM_AUTH_PERMISSION_NETWORK_CONTROL);
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

	if (!return_no_pk_error (priv->authority, "Permissions", context))
		return;

	chain = nm_auth_chain_new (priv->authority, context, NULL, get_permissions_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);

	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SLEEP_WAKE, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_USE_USER_CONNECTIONS, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, FALSE);
}

/* Legacy 0.6 compatibility interface */

static void
impl_manager_legacy_sleep (NMManager *manager, DBusGMethodInvocation *context)
{
	return impl_manager_sleep (manager, TRUE, context);
}

static void
impl_manager_legacy_wake  (NMManager *manager, DBusGMethodInvocation *context)
{
	return impl_manager_sleep (manager, FALSE, context);
}

static gboolean
impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	nm_manager_update_state (manager);
	*state = priv->state;
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

/* Connections */

gboolean
nm_manager_auto_user_connections_allowed (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	return    priv->user_net_perm == NM_AUTH_CALL_RESULT_YES
	       && priv->user_con_perm == NM_AUTH_CALL_RESULT_YES;
}

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
		nm_log_err (LOGD_CORE, "unknown NMConnectionScope %d", scope);
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
		nm_log_err (LOGD_CORE, "unknown NMConnectionScope %d", scope);
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
	guint i;

	/* Set initial radio enabled/disabled state */
	for (i = 0; i < RFKILL_TYPE_MAX; i++) {
		RadioState *rstate = &priv->radio_states[i];
		gboolean enabled = TRUE, hw_enabled = TRUE;

		if (!rstate->desc)
			continue;

		switch (nm_udev_manager_get_rfkill_state (priv->udev_mgr, i)) {
		case RFKILL_UNBLOCKED:
			enabled = TRUE;
			hw_enabled = TRUE;
			break;
		case RFKILL_SOFT_BLOCKED:
			enabled = FALSE;
			hw_enabled = TRUE;
			break;
		case RFKILL_HARD_BLOCKED:
			enabled = FALSE;
			hw_enabled = FALSE;
			break;
		default:
			break;
		}

		rstate->hw_enabled = hw_enabled;
		nm_log_info (LOGD_RFKILL, "%s %s by radio killswitch; %s by state file",
		             rstate->desc,
		             (rstate->hw_enabled && enabled) ? "enabled" : "disabled",
		             (rstate->enabled) ? "enabled" : "disabled");
		manager_set_radio_enabled (self, rstate, rstate->enabled && enabled);
	}

	/* Log overall networking status - enabled/disabled */
	nm_log_info (LOGD_CORE, "Networking is %s by state file",
	             priv->net_enabled ? "enabled" : "disabled");

	system_unmanaged_devices_changed_cb (priv->sys_settings, NULL, self);
	system_hostname_changed_cb (priv->sys_settings, NULL, self);
	system_query_connections (self);

	/* Get user connections if the user settings service is around, otherwise
	 * they will be queried when the user settings service shows up on the
	 * bus in nm_manager_name_owner_changed().
	 */
	if (nm_dbus_manager_name_has_owner (priv->dbus_mgr, NM_DBUS_SERVICE_USER_SETTINGS))
		user_proxy_init (self);

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

NMManager *
nm_manager_get (const char *config_file,
                const char *plugins,
                const char *state_file,
                gboolean initial_net_enabled,
                gboolean initial_wifi_enabled,
                gboolean initial_wwan_enabled,
                GError **error)
{
	static NMManager *singleton = NULL;
	NMManagerPrivate *priv;
	DBusGConnection *bus;

	if (singleton)
		return g_object_ref (singleton);

	singleton = (NMManager *) g_object_new (NM_TYPE_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_MANAGER_GET_PRIVATE (singleton);

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	g_assert (bus);

	priv->sys_settings = nm_sysconfig_settings_new (config_file, plugins, bus, error);
	if (!priv->sys_settings) {
		g_object_unref (singleton);
		return NULL;
	}
	nm_settings_service_export (NM_SETTINGS_SERVICE (priv->sys_settings));

	priv->config_file = g_strdup (config_file);

	priv->state_file = g_strdup (state_file);

	priv->net_enabled = initial_net_enabled;

	priv->radio_states[RFKILL_TYPE_WLAN].enabled = initial_wifi_enabled;
	priv->radio_states[RFKILL_TYPE_WWAN].enabled = initial_wwan_enabled;

	g_signal_connect (priv->sys_settings, "notify::" NM_SYSCONFIG_SETTINGS_UNMANAGED_SPECS,
	                  G_CALLBACK (system_unmanaged_devices_changed_cb), singleton);
	g_signal_connect (priv->sys_settings, "notify::" NM_SETTINGS_SYSTEM_INTERFACE_HOSTNAME,
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
	GSList *iter;

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	for (iter = priv->pending_activations; iter; iter = g_slist_next (iter))
		pending_activation_destroy ((PendingActivation *) iter->data, NULL, NULL);
	g_slist_free (priv->pending_activations);
	priv->pending_activations = NULL;

	g_slist_foreach (priv->auth_chains, (GFunc) nm_auth_chain_unref, NULL);
	g_slist_free (priv->auth_chains);
	g_object_unref (priv->authority);

	while (g_slist_length (priv->secrets_calls))
		free_get_secrets_info ((GetSecretsInfo *) priv->secrets_calls->data);

	while (g_slist_length (priv->devices)) {
		priv->devices = remove_one_device (manager,
		                                   priv->devices,
		                                   NM_DEVICE (priv->devices->data),
		                                   TRUE,
		                                   FALSE);
	}

	user_proxy_cleanup (manager, FALSE);
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

	if (priv->fw_monitor) {
		if (priv->fw_monitor_id)
			g_signal_handler_disconnect (priv->fw_monitor, priv->fw_monitor_id);

		if (priv->fw_changed_id)
			g_source_remove (priv->fw_changed_id);

		g_file_monitor_cancel (priv->fw_monitor);
		g_object_unref (priv->fw_monitor);
	}

	G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
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
		manager_set_radio_enabled (NM_MANAGER (object),
		                           &priv->radio_states[RFKILL_TYPE_WLAN],
		                           g_value_get_boolean (value));
		break;
	case PROP_WWAN_ENABLED:
		manager_set_radio_enabled (NM_MANAGER (object),
		                           &priv->radio_states[RFKILL_TYPE_WWAN],
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
	case PROP_STATE:
		nm_manager_update_state (self);
		g_value_set_uint (value, priv->state);
		break;
	case PROP_NETWORKING_ENABLED:
		g_value_set_boolean (value, priv->net_enabled);
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, priv->radio_states[RFKILL_TYPE_WLAN].enabled);
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->radio_states[RFKILL_TYPE_WLAN].hw_enabled);
		break;
	case PROP_WWAN_ENABLED:
		g_value_set_boolean (value, priv->radio_states[RFKILL_TYPE_WWAN].enabled);
		break;
	case PROP_WWAN_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->radio_states[RFKILL_TYPE_WWAN].hw_enabled);
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

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *g_connection;
	guint id, i;
	GFile *file;

	/* Initialize rfkill structures and states */
	memset (priv->radio_states, 0, sizeof (priv->radio_states));

	priv->radio_states[RFKILL_TYPE_WLAN].enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WLAN].key = "WirelessEnabled";
	priv->radio_states[RFKILL_TYPE_WLAN].prop = NM_MANAGER_WIRELESS_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].hw_prop = NM_MANAGER_WIRELESS_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].desc = "WiFi";
	priv->radio_states[RFKILL_TYPE_WLAN].other_enabled_func = nm_manager_get_ipw_rfkill_state;
	priv->radio_states[RFKILL_TYPE_WLAN].rtype = RFKILL_TYPE_WLAN;

	priv->radio_states[RFKILL_TYPE_WWAN].enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WWAN].key = "WWANEnabled";
	priv->radio_states[RFKILL_TYPE_WWAN].prop = NM_MANAGER_WWAN_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].hw_prop = NM_MANAGER_WWAN_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].desc = "WWAN";
	priv->radio_states[RFKILL_TYPE_WWAN].other_enabled_func = nm_manager_get_modem_enabled_state;
	priv->radio_states[RFKILL_TYPE_WWAN].rtype = RFKILL_TYPE_WWAN;

	priv->radio_states[RFKILL_TYPE_WIMAX].enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WIMAX].key = "WiMAXEnabled";
	priv->radio_states[RFKILL_TYPE_WIMAX].prop = NULL;
	priv->radio_states[RFKILL_TYPE_WIMAX].hw_prop = NULL;
	priv->radio_states[RFKILL_TYPE_WIMAX].desc = "WiMAX";
	priv->radio_states[RFKILL_TYPE_WIMAX].other_enabled_func = NULL;
	priv->radio_states[RFKILL_TYPE_WIMAX].rtype = RFKILL_TYPE_WIMAX;

	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		priv->radio_states[i].hw_enabled = TRUE;

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

	priv->authority = polkit_authority_get ();
	if (priv->authority) {
		priv->auth_changed_id = g_signal_connect (priv->authority,
		                                          "changed",
		                                          G_CALLBACK (pk_authority_changed_cb),
		                                          manager);
	} else
		nm_log_warn (LOGD_CORE, "failed to create PolicyKit authority.");

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
	dbus_g_error_domain_register (NM_LOGGING_ERROR, "org.freedesktop.NetworkManager.Logging", NM_TYPE_LOGGING_ERROR);
}

