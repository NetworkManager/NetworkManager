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
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#include <config.h>

#include <stdlib.h>
#include <netinet/ether.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include "nm-device.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-modem.h"
#include "nm-device-infiniband.h"
#include "nm-device-bond.h"
#include "nm-device-team.h"
#include "nm-device-bridge.h"
#include "nm-device-vlan.h"
#include "nm-device-adsl.h"
#include "nm-device-generic.h"
#include "nm-device-veth.h"
#include "nm-device-tun.h"
#include "nm-device-macvlan.h"
#include "nm-device-gre.h"
#include "nm-setting-private.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-vpn.h"
#include "nm-dbus-glib-types.h"
#include "nm-platform.h"
#include "nm-atm-manager.h"
#include "nm-rfkill-manager.h"
#include "nm-hostname-provider.h"
#include "nm-bluez-manager.h"
#include "nm-bluez-common.h"
#include "nm-settings.h"
#include "nm-settings-connection.h"
#include "nm-manager-auth.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-device-factory.h"
#include "nm-enum-types.h"
#include "nm-sleep-monitor.h"
#include "nm-connectivity.h"
#include "nm-policy.h"


#define NM_AUTOIP_DBUS_SERVICE "org.freedesktop.nm_avahi_autoipd"
#define NM_AUTOIP_DBUS_IFACE   "org.freedesktop.nm_avahi_autoipd"

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

static void impl_manager_get_logging (NMManager *manager,
                                      char **level,
                                      char **domains);

static void impl_manager_check_connectivity (NMManager *manager,
                                             DBusGMethodInvocation *context);

#include "nm-manager-glue.h"

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

static void add_device (NMManager *self, NMDevice *device);
static void remove_device (NMManager *self, NMDevice *device, gboolean quitting);

static void hostname_provider_init (NMHostnameProvider *provider_class);

static NMActiveConnection *internal_activate_device (NMManager *manager,
                                                     NMDevice *device,
                                                     NMConnection *connection,
                                                     const char *specific_object,
                                                     gboolean user_requested,
                                                     gulong sender_uid,
                                                     const char *dbus_sender,
                                                     gboolean assumed,
                                                     NMActiveConnection *master,
                                                     GError **error);

static NMDevice *find_device_by_ip_iface (NMManager *self, const gchar *iface);

static void rfkill_change_wifi (const char *desc, gboolean enabled);

static void
platform_link_added_cb (NMPlatform *platform,
                        int ifindex,
                        NMPlatformLink *link,
                        NMPlatformReason reason,
                        gpointer user_data);

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
	const char *wifi_shared_permission;

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
	char *state_file;

	GSList *active_connections;
	guint ac_cleanup_id;
	NMActiveConnection *primary_connection;
	NMActiveConnection *activating_connection;

	GSList *devices;
	NMState state;
	NMConnectivity *connectivity;

	NMPolicy *policy;

	NMDBusManager *dbus_mgr;
	guint          dbus_connection_changed_id;
	NMAtmManager *atm_mgr;
	NMRfkillManager *rfkill_mgr;
	NMBluezManager *bluez_mgr;

	/* List of NMDeviceFactoryFunc pointers sorted in priority order */
	GSList *factories;

	NMSettings *settings;
	char *hostname;

	RadioState radio_states[RFKILL_TYPE_MAX];
	gboolean sleeping;
	gboolean net_enabled;

	NMVPNManager *vpn_manager;

	NMModemManager *modem_manager;
	guint modem_added_id;
	guint modem_removed_id;

	DBusGProxy *aipd_proxy;
	NMSleepMonitor *sleep_monitor;

	GSList *auth_chains;

	/* Firmware dir monitor */
	GFileMonitor *fw_monitor;
	guint fw_monitor_id;
	guint fw_changed_id;

	guint timestamp_update_id;

	GHashTable *nm_bridges;

	gboolean startup;
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
	CHECK_PERMISSIONS,
	USER_PERMISSIONS_CHANGED,
	ACTIVE_CONNECTION_ADDED,
	ACTIVE_CONNECTION_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

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
	PROP_PRIMARY_CONNECTION,
	PROP_ACTIVATING_CONNECTION,

	/* Not exported */
	PROP_HOSTNAME,
	PROP_SLEEPING,

	LAST_PROP
};


/************************************************************************/

#define NM_MANAGER_ERROR (nm_manager_error_quark ())

static GQuark
nm_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-manager-error");
	return quark;
}

/************************************************************************/

static void active_connection_state_changed (NMActiveConnection *active,
                                             GParamSpec *pspec,
                                             NMManager *self);

static gboolean
_active_connection_cleanup (gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	gboolean changed = FALSE;

	priv->ac_cleanup_id = 0;

	iter = priv->active_connections;
	while (iter) {
		NMActiveConnection *ac = iter->data;

		iter = iter->next;
		if (nm_active_connection_get_state (ac) == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
			priv->active_connections = g_slist_remove (priv->active_connections, ac);
			g_signal_emit (self, signals[ACTIVE_CONNECTION_REMOVED], 0, ac);
			g_signal_handlers_disconnect_by_func (ac, active_connection_state_changed, self);
			g_object_unref (ac);
			changed = TRUE;
		}
	}

	if (changed)
		g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);

	return FALSE;
}

static void
active_connection_state_changed (NMActiveConnection *active,
                                 GParamSpec *pspec,
                                 NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnectionState state;

	state = nm_active_connection_get_state (active);
	if (state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		/* Destroy active connections from an idle handler to ensure that
		 * their last property change notifications go out, which wouldn't
		 * happen if we destroyed them immediately when their state was set
		 * to DEACTIVATED.
		 */
		if (!priv->ac_cleanup_id)
			priv->ac_cleanup_id = g_idle_add (_active_connection_cleanup, self);
	}
}

static void
active_connection_add (NMManager *self, NMActiveConnection *active)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (g_slist_find (priv->active_connections, active) == FALSE);

	priv->active_connections = g_slist_prepend (priv->active_connections, active);
	g_signal_connect (active, "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  G_CALLBACK (active_connection_state_changed),
	                  self);

	g_signal_emit (self, signals[ACTIVE_CONNECTION_ADDED], 0, active);
	g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
}

const GSList *
nm_manager_get_active_connections (NMManager *manager)
{
	return NM_MANAGER_GET_PRIVATE (manager)->active_connections;
}

static NMActiveConnection *
active_connection_get_by_path (NMManager *manager, const char *path)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	for (iter = priv->active_connections; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *candidate = iter->data;

		if (strcmp (path, nm_active_connection_get_path (candidate)) == 0)
			return candidate;
	}
	return NULL;
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

NMDevice *
nm_manager_get_device_by_master (NMManager *manager, const char *master, const char *driver)
{
	GSList *iter;

	g_return_val_if_fail (master != NULL, NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_iface (device), master) &&
		    (!driver || !strcmp (nm_device_get_driver (device), driver)))
			return device;
	}

	return NULL;
}

NMDevice *
nm_manager_get_device_by_ifindex (NMManager *manager, int ifindex)
{
	GSList *iter;

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_get_ifindex (device) == ifindex)
			return device;
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
modem_added (NMModemManager *modem_manager,
			 NMModem *modem,
			 const char *driver,
			 gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *replace_device, *device = NULL;
	const char *modem_iface;
	GSList *iter;

	/* Don't rely only on the data port; use the control port if available */
	modem_iface = nm_modem_get_data_port (modem);
	if (!modem_iface)
		modem_iface = nm_modem_get_control_port (modem);
	g_return_if_fail (modem_iface);

	replace_device = find_device_by_ip_iface (NM_MANAGER (user_data), modem_iface);
	if (replace_device)
		remove_device (NM_MANAGER (user_data), replace_device, FALSE);

	/* Give Bluetooth DUN devices first chance to claim the modem */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		if (nm_device_get_device_type (iter->data) == NM_DEVICE_TYPE_BT) {
			if (nm_device_bt_modem_added (NM_DEVICE_BT (iter->data), modem, driver))
				return;
		}
	}

	/* If it was a Bluetooth modem and no bluetooth device claimed it, ignore
	 * it.  The rfcomm port (and thus the modem) gets created automatically
	 * by the Bluetooth code during the connection process.
	 */
	if (driver && !strcmp (driver, "bluetooth")) {
		nm_log_info (LOGD_MB, "ignoring modem '%s' (no associated Bluetooth device)", modem_iface);
		return;
	}

	/* Make the new modem device */
	device = nm_device_modem_new (modem, driver);
	if (device)
		add_device (self, device);
}

static void
set_state (NMManager *manager, NMState state)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const char *state_str;

	if (priv->state == state)
		return;

	priv->state = state;

	switch (state) {
	case NM_STATE_ASLEEP:
		state_str = "ASLEEP";
		break;
	case NM_STATE_DISCONNECTED:
		state_str = "DISCONNECTED";
		break;
	case NM_STATE_DISCONNECTING:
		state_str = "DISCONNECTING";
		break;
	case NM_STATE_CONNECTING:
		state_str = "CONNECTING";
		break;
	case NM_STATE_CONNECTED_LOCAL:
		state_str = "CONNECTED_LOCAL";
		break;
	case NM_STATE_CONNECTED_SITE:
		state_str = "CONNECTED_SITE";
		break;
	case NM_STATE_CONNECTED_GLOBAL:
		state_str = "CONNECTED_GLOBAL";
		break;
	case NM_STATE_UNKNOWN:
	default:
		state_str = "UNKNOWN";
		break;
	}

	nm_log_info (LOGD_CORE, "NetworkManager state is now %s", state_str);

	g_object_notify (G_OBJECT (manager), NM_MANAGER_STATE);
	g_signal_emit (manager, signals[STATE_CHANGED], 0, priv->state);
}

static void
checked_connectivity (GObject *object, GAsyncResult *result, gpointer user_data)
{
	NMManager *manager = user_data;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnectivityState connectivity;

	if (priv->state == NM_STATE_CONNECTING || priv->state == NM_STATE_CONNECTED_SITE) {
		connectivity = nm_connectivity_check_finish (priv->connectivity, result, NULL);

		if (connectivity == NM_CONNECTIVITY_FULL)
			set_state (manager, NM_STATE_CONNECTED_GLOBAL);
		else if (   connectivity == NM_CONNECTIVITY_PORTAL
		         || connectivity == NM_CONNECTIVITY_LIMITED)
			set_state (manager, NM_STATE_CONNECTED_SITE);
	}

	g_object_unref (manager);
}

static void
nm_manager_update_state (NMManager *manager)
{
	NMManagerPrivate *priv;
	NMState new_state = NM_STATE_DISCONNECTED;
	GSList *iter;
	gboolean want_connectivity_check = FALSE;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (manager_sleeping (manager))
		new_state = NM_STATE_ASLEEP;
	else {
		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *dev = NM_DEVICE (iter->data);
			NMDeviceState state = nm_device_get_state (dev);

			if (state == NM_DEVICE_STATE_ACTIVATED) {
				nm_connectivity_set_online (priv->connectivity, TRUE);
				if (nm_connectivity_get_state (priv->connectivity) != NM_CONNECTIVITY_FULL) {
					new_state = NM_STATE_CONNECTING;
					want_connectivity_check = TRUE;
				} else {
					new_state = NM_STATE_CONNECTED_GLOBAL;
					break;
				}
			}

			if (nm_device_is_activating (dev))
				new_state = NM_STATE_CONNECTING;
			else if (new_state != NM_STATE_CONNECTING) {
				if (state == NM_DEVICE_STATE_DEACTIVATING)
					new_state = NM_STATE_DISCONNECTING;
			}
		}
	}

	if (new_state == NM_STATE_CONNECTING && want_connectivity_check) {
		nm_connectivity_check_async (priv->connectivity,
		                             checked_connectivity,
		                             g_object_ref (manager));
		return;
	}

	nm_connectivity_set_online (priv->connectivity, new_state >= NM_STATE_CONNECTED_LOCAL);
	set_state (manager, new_state);
}

static void
manager_device_state_changed (NMDevice *device,
                              NMDeviceState new_state,
                              NMDeviceState old_state,
                              NMDeviceStateReason reason,
                              gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_FAILED:
		g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
		break;
	default:
		break;
	}

	nm_manager_update_state (self);
}

static void device_has_pending_action_changed (NMDevice *device,
                                               GParamSpec *pspec,
                                               NMManager *self);

static void
check_if_startup_complete (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	if (!priv->startup)
		return;

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *dev = iter->data;

		if (nm_device_has_pending_action (dev)) {
			nm_log_dbg (LOGD_CORE, "check_if_startup_complete returns FALSE because of %s",
			            nm_device_get_iface (dev));
			return;
		}
	}

	nm_log_info (LOGD_CORE, "startup complete");

	priv->startup = FALSE;
	g_object_notify (G_OBJECT (self), "startup");

	/* We don't have to watch notify::has-pending-action any more. */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *dev = iter->data;

		g_signal_handlers_disconnect_by_func (dev, G_CALLBACK (device_has_pending_action_changed), self);
	}
}

static void
device_has_pending_action_changed (NMDevice *device,
                                   GParamSpec *pspec,
                                   NMManager *self)
{
	check_if_startup_complete (self);
}

static void
remove_device (NMManager *manager, NMDevice *device, gboolean quitting)
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

		if (   !nm_device_can_assume_connections (device)
		    || (nm_device_get_state (device) != NM_DEVICE_STATE_ACTIVATED)
		    || !quitting)
			nm_device_set_manager_managed (device, FALSE, NM_DEVICE_STATE_REASON_REMOVED);
	}

	g_signal_handlers_disconnect_matched (device, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, manager);

	nm_settings_device_removed (priv->settings, device);
	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, device);
	g_object_unref (device);

	priv->devices = g_slist_remove (priv->devices, device);

	if (priv->startup)
		check_if_startup_complete (manager);
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
		if (nm_device_get_device_type (iter->data) == NM_DEVICE_TYPE_BT) {
			if (nm_device_bt_modem_removed (NM_DEVICE_BT (iter->data), modem))
				return;
		}
	}

	/* Otherwise remove the standalone modem */
	found = nm_manager_get_device_by_udi (self, nm_modem_get_path (modem));
	if (found)
		remove_device (self, found, FALSE);
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

	if (nm_connection_get_setting_vpn (connection))
		return TRUE;

	/* Make sure it's not a VPN, which we can't autocomplete yet */
	s_con = nm_connection_get_setting_connection (connection);
	if (s_con)
		ctype = nm_setting_connection_get_connection_type (s_con);

	return (g_strcmp0 (ctype, NM_SETTING_VPN_SETTING_NAME) == 0);
}

static gboolean
try_complete_vpn (NMConnection *connection, GSList *existing, GError **error)
{
	g_assert (might_be_vpn (connection) == TRUE);

	if (!nm_connection_get_setting_vpn (connection)) {
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

	pending->connection_path = g_strdup (connection_path);
	pending->connection = connection;

	/* "/" is special-cased to NULL to get through D-Bus */
	if (specific_object_path && strcmp (specific_object_path, "/"))
		pending->specific_object_path = g_strdup (specific_object_path);
	if (device_path && strcmp (device_path, "/"))
		pending->device_path = g_strdup (device_path);

	return pending;
}

static void
pending_auth_done (NMAuthChain *chain,
                   GError *error,
                   DBusGMethodInvocation *context,
                   gpointer user_data)
{
	PendingActivation *pending = user_data;
	NMAuthCallResult result;
	GError *tmp_error = NULL;

	/* Caller has had a chance to obtain authorization, so we only need to
	 * check for 'yes' here.
	 */
	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL);
	if (error)
		tmp_error = g_error_copy (error);
	else if (result != NM_AUTH_CALL_RESULT_YES) {
		tmp_error = g_error_new_literal (NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
		                                 "Not authorized to control networking.");
	} else if (pending->wifi_shared_permission) {
		result = nm_auth_chain_get_result (chain, pending->wifi_shared_permission);
		if (result != NM_AUTH_CALL_RESULT_YES) {
			tmp_error = g_error_new_literal (NM_MANAGER_ERROR,
			                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
			                                 "Not authorized to share connections via wifi.");
		}
	}

	pending->callback (pending, tmp_error);
	g_clear_error (&tmp_error);
}

static void
pending_activation_check_authorized (PendingActivation *pending)
{
	GError *error;
	const char *wifi_permission = NULL;
	NMConnection *connection;
	NMSettings *settings;
	const char *error_desc = NULL;

	g_return_if_fail (pending != NULL);

	/* By this point we have an auto-completed connection (for AddAndActivate)
	 * or an existing connection (for Activate).
	 */
	connection = pending->connection;
	if (!connection) {
		settings = NM_MANAGER_GET_PRIVATE (pending->manager)->settings;
		connection = (NMConnection *) nm_settings_get_connection_by_path (settings, pending->connection_path);
	}

	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "Connection could not be found.");
		pending->callback (pending, error);
		g_error_free (error);
		return;
	}

	/* First check if the user is allowed to use networking at all, giving
	 * the user a chance to authenticate to gain the permission.
	 */
	pending->chain = nm_auth_chain_new (pending->context,
	                                    pending_auth_done,
	                                    pending,
	                                    &error_desc);
	if (pending->chain) {
		nm_auth_chain_add_call (pending->chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);

		/* Shared wifi connections require special permissions too */
		wifi_permission = nm_utils_get_shared_wifi_permission (connection);
		if (wifi_permission) {
			pending->wifi_shared_permission = wifi_permission;
			nm_auth_chain_add_call (pending->chain, wifi_permission, TRUE);
		}
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		pending->callback (pending, error);
		g_error_free (error);
	}
}

static void
pending_activation_destroy (PendingActivation *pending,
                            GError *error,
                            NMActiveConnection *ac)
{
	g_return_if_fail (pending != NULL);

	if (error)
		dbus_g_method_return_error (pending->context, error);
	else if (ac) {
		if (pending->connection) {
			dbus_g_method_return (pending->context,
			                      pending->connection_path,
			                      nm_active_connection_get_path (ac));
		} else {
			dbus_g_method_return (pending->context,
			                      nm_active_connection_get_path (ac));
		}
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

/*******************************************************************/
/* Settings stuff via NMSettings                                   */
/*******************************************************************/

static NMDevice *
get_device_from_hwaddr (NMManager *self, NMConnection *connection)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		if (nm_device_hwaddr_matches (NM_DEVICE (iter->data), connection, NULL, 0, TRUE))
			return iter->data;
	}
	return NULL;
}

static NMDevice*
find_vlan_parent (NMManager *self,
                  NMConnection *connection,
                  gboolean check_hwaddr)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMSettingVlan *s_vlan;
	NMConnection *parent_connection;
	const char *parent_iface;
	NMDevice *parent = NULL;
	GSList *iter;

	/* The 'parent' property could be either an interface name, a connection
	 * UUID, or even given by the MAC address of the connection's ethernet
	 * or WiFi setting.
	 */
	s_vlan = nm_connection_get_setting_vlan (connection);
	g_return_val_if_fail (s_vlan != NULL, NULL);

	parent_iface = nm_setting_vlan_get_parent (s_vlan);
	if (parent_iface) {
		parent = find_device_by_ip_iface (self, parent_iface);
		if (parent)
			return parent;

		if (nm_utils_is_uuid (parent_iface)) {
			/* Try as a connection UUID */
			parent_connection = (NMConnection *) nm_settings_get_connection_by_uuid (priv->settings, parent_iface);
			if (parent_connection) {
				/* Check if the parent connection is activated on some device already */
				for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
					NMActRequest *req;
					NMConnection *candidate;

					req = nm_device_get_act_request (NM_DEVICE (iter->data));
					if (req) {
						candidate = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (req));
						if (candidate == parent_connection)
							return NM_DEVICE (iter->data);
					}
				}

				/* Check the hardware address of the parent connection */
				if (check_hwaddr)
					return get_device_from_hwaddr (self, parent_connection);
			}
			return NULL;
		}
	}

	/* Try the hardware address from the VLAN connection's hardware setting */
	if (check_hwaddr)
		return get_device_from_hwaddr (self, connection);

	return NULL;
}

static NMDevice *
find_infiniband_parent (NMManager *self,
                        NMConnection *connection)
{
	NMSettingInfiniband *s_infiniband;
	const char *parent_iface;
	NMDevice *parent = NULL;

	s_infiniband = nm_connection_get_setting_infiniband (connection);
	g_return_val_if_fail (s_infiniband != NULL, NULL);

	parent_iface = nm_setting_infiniband_get_parent (s_infiniband);
	if (parent_iface) {
		parent = find_device_by_ip_iface (self, parent_iface);
		if (parent)
			return parent;
	}

	return get_device_from_hwaddr (self, connection);
}

/**
 * get_virtual_iface_name:
 * @self: the #NMManager
 * @connection: the #NMConnection representing a virtual interface
 * @out_parent: on success, the parent device if any
 *
 * Given @connection, returns the interface name that the connection
 * would represent.  If the interface name is not given by the connection,
 * this may require constructing it based on information in the connection
 * and existing network interfaces.
 *
 * Returns: the expected interface name (caller takes ownership), or %NULL
 */
static char *
get_virtual_iface_name (NMManager *self,
                        NMConnection *connection,
                        NMDevice **out_parent)
{
	NMDevice *parent = NULL;

	if (out_parent)
		*out_parent = NULL;

	if (nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME))
		return g_strdup (nm_connection_get_virtual_iface_name (connection));

	if (nm_connection_is_type (connection, NM_SETTING_TEAM_SETTING_NAME))
		return g_strdup (nm_connection_get_virtual_iface_name (connection));

	if (nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME))
		return g_strdup (nm_connection_get_virtual_iface_name (connection));

	if (nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME)) {
		NMSettingVlan *s_vlan;
		const char *ifname;
		char *vname;

		s_vlan = nm_connection_get_setting_vlan (connection);
		g_return_val_if_fail (s_vlan != NULL, NULL);

		parent = find_vlan_parent (self, connection, TRUE);
		if (parent) {
			ifname = nm_connection_get_virtual_iface_name (connection);

			if (!nm_device_supports_vlans (parent)) {
				nm_log_warn (LOGD_DEVICE, "(%s): No support for VLANs on interface %s of type %s",
				             ifname ? ifname : nm_connection_get_id (connection),
				             nm_device_get_ip_iface (parent),
				             nm_device_get_type_desc (parent));
				return NULL;
			}

			/* If the connection doesn't specify the interface name for the VLAN
			 * device, we create one for it using the VLAN ID and the parent
			 * interface's name.
			 */
			if (ifname)
				vname = g_strdup (ifname);
			else {
				vname = nm_utils_new_vlan_name (nm_device_get_ip_iface (parent),
				                                nm_setting_vlan_get_id (s_vlan));
			}
			if (out_parent)
				*out_parent = parent;
			return vname;
		}
	}

	if (nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		const char *ifname;
		char *name;

		parent = find_infiniband_parent (self, connection);
		if (parent) {
			ifname = nm_connection_get_virtual_iface_name (connection);
			if (ifname)
				name = g_strdup (ifname);
			else {
				NMSettingInfiniband *s_infiniband;
				int p_key;

				ifname = nm_device_get_iface (parent);
				s_infiniband = nm_connection_get_setting_infiniband (connection);
				p_key = nm_setting_infiniband_get_p_key (s_infiniband);
				name = g_strdup_printf ("%s.%04x", ifname, p_key);
			}
			if (out_parent)
				*out_parent = parent;
			return name;
		}
	}

	return NULL;
}

static gboolean
connection_needs_virtual_device (NMConnection *connection)
{
	if (   nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_TEAM_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME)
	    || nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME))
		return TRUE;

	if (nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		NMSettingInfiniband *s_infiniband;

		s_infiniband = nm_connection_get_setting_infiniband (connection);
		g_return_val_if_fail (s_infiniband != NULL, FALSE);
		if (nm_setting_infiniband_get_p_key (s_infiniband) != -1)
			return TRUE;
	}

	return FALSE;
}

/***************************/

/* FIXME: remove when we handle bridges non-destructively */

#define NM_BRIDGE_FILE  NMRUNDIR "/nm-bridges"

static void
read_nm_created_bridges (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	char *contents;
	char **lines, **iter;
	GTimeVal tv;
	glong ts;

	if (!g_file_get_contents (NM_BRIDGE_FILE, &contents, NULL, NULL))
		return;

	g_get_current_time (&tv);

	lines = g_strsplit_set (contents, "\n", 0);
	g_free (contents);

	for (iter = lines; iter && *iter; iter++) {
		if (g_str_has_prefix (*iter, "ts=")) {
			errno = 0;
			ts = strtol (*iter + 3, NULL, 10);
			/* allow 30 minutes time difference before we ignore the file */
			if (errno || ABS (tv.tv_sec - ts) > 1800)
				goto out;
		} else if (g_str_has_prefix (*iter, "iface="))
			g_hash_table_insert (priv->nm_bridges, g_strdup (*iter + 6), GUINT_TO_POINTER (1));
	}

out:
	g_strfreev (lines);
	unlink (NM_BRIDGE_FILE);
}

static void
write_nm_created_bridges (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GString *br_list;
	GSList *iter;
	GError *error = NULL;
	GTimeVal tv;
	gboolean found = FALSE;

	/* write out nm-created bridges list */
	br_list = g_string_sized_new (50);

	/* Timestamp is first line */
	g_get_current_time (&tv);
	g_string_append_printf (br_list, "ts=%ld\n", tv.tv_sec);

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = iter->data;

		if (nm_device_get_device_type (device) == NM_DEVICE_TYPE_BRIDGE) {
			g_string_append_printf (br_list, "iface=%s\n", nm_device_get_iface (device));
			found = TRUE;
		}
	}

	if (found) {
		if (!g_file_set_contents (NM_BRIDGE_FILE, br_list->str, -1, &error)) {
			nm_log_warn (LOGD_BRIDGE, "Failed to write NetworkManager-created bridge list; "
			             "on restart bridges may not be recognized. (%s)",
			             error ? error->message : "unknown");
			g_clear_error (&error);
		}
	}
	g_string_free (br_list, TRUE);
}

static gboolean
bridge_created_by_nm (NMManager *self, const char *iface)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	return (priv->nm_bridges && g_hash_table_lookup (priv->nm_bridges, iface));
}

/***************************/

/**
 * system_create_virtual_device:
 * @self: the #NMManager
 * @connection: the connection which might require a virtual device
 *
 * If @connection requires a virtual device and one does not yet exist for it,
 * creates that device.
 *
 * Returns: the #NMDevice if successfully created, %NULL if not
 */
static NMDevice *
system_create_virtual_device (NMManager *self, NMConnection *connection)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;
	char *iface = NULL;
	NMDevice *device = NULL, *parent = NULL;

	iface = get_virtual_iface_name (self, connection, &parent);
	if (!iface) {
		nm_log_warn (LOGD_DEVICE, "(%s) failed to determine virtual interface name",
		             nm_connection_get_id (connection));
		return NULL;
	}

	/* Make sure we didn't create a device for this connection already */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = iter->data;
		GError *error = NULL;

		if (   g_strcmp0 (nm_device_get_iface (candidate), iface) == 0
		    || nm_device_check_connection_compatible (candidate, connection, &error)) {
			g_clear_error (&error);
			goto out;
		}
		g_clear_error (&error);
	}

	/* Block notification of link added since we're creating the device
	 * explicitly here, otherwise adding the platform/kernel device would
	 * create it before this function can do the rest of the setup.
	 */
	g_signal_handlers_block_by_func (nm_platform_get (), G_CALLBACK (platform_link_added_cb), self);

	if (nm_connection_is_type (connection, NM_SETTING_BOND_SETTING_NAME)) {

		if (   !nm_platform_bond_add (iface)
		    && nm_platform_get_error () != NM_PLATFORM_ERROR_EXISTS) {
			nm_log_warn (LOGD_DEVICE, "(%s): failed to add bonding master interface for '%s'",
			             iface, nm_connection_get_id (connection));
			goto unblock;
		}

		device = nm_device_bond_new (iface);
	} else if (nm_connection_is_type (connection, NM_SETTING_TEAM_SETTING_NAME)) {
		if (!nm_platform_team_add (iface)
		    && nm_platform_get_error () != NM_PLATFORM_ERROR_EXISTS) {
			nm_log_warn (LOGD_DEVICE, "(%s): failed to add team master interface for '%s'",
			             iface, nm_connection_get_id (connection));
			goto unblock;
		}

		device = nm_device_team_new (iface);
	} else if (nm_connection_is_type (connection, NM_SETTING_BRIDGE_SETTING_NAME)) {
		gboolean result;

		result = nm_platform_bridge_add (iface);
		if (!result && nm_platform_get_error () != NM_PLATFORM_ERROR_EXISTS) {
			nm_log_warn (LOGD_DEVICE, "(%s): failed to add bridging interface for '%s'",
			             iface, nm_connection_get_id (connection));
			goto unblock;
		}

		/* FIXME: remove when we handle bridges non-destructively */
		if (!result && !bridge_created_by_nm (self, iface)) {
			nm_log_warn (LOGD_DEVICE, "(%s): cannot use existing bridge for '%s'",
			             iface, nm_connection_get_id (connection));
			goto unblock;
		}

		device = nm_device_bridge_new (iface);
	} else if (nm_connection_is_type (connection, NM_SETTING_VLAN_SETTING_NAME)) {
		NMSettingVlan *s_vlan = nm_connection_get_setting_vlan (connection);
		int ifindex = nm_device_get_ip_ifindex (parent);
		int num, i;
		guint32 from, to;

		if (   !nm_platform_vlan_add (iface, ifindex,
		           nm_setting_vlan_get_id (s_vlan),
		           nm_setting_vlan_get_flags (s_vlan))
		    && nm_platform_get_error () != NM_PLATFORM_ERROR_EXISTS) {
			nm_log_warn (LOGD_DEVICE, "(%s): failed to add VLAN interface for '%s'",
			             iface, nm_connection_get_id (connection));
			goto unblock;
		}
		num = nm_setting_vlan_get_num_priorities (s_vlan, NM_VLAN_INGRESS_MAP);
		for (i = 0; i < num; i++) {
			if (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_INGRESS_MAP, i, &from, &to))
				nm_platform_vlan_set_ingress_map (ifindex, from, to);
		}
		num = nm_setting_vlan_get_num_priorities (s_vlan, NM_VLAN_EGRESS_MAP);
		for (i = 0; i < num; i++) {
			if (nm_setting_vlan_get_priority (s_vlan, NM_VLAN_EGRESS_MAP, i, &from, &to))
				nm_platform_vlan_set_egress_map (ifindex, from, to);
		}
		device = nm_device_vlan_new (iface, parent);
	} else if (nm_connection_is_type (connection, NM_SETTING_INFINIBAND_SETTING_NAME)) {
		NMSettingInfiniband *s_infiniband = nm_connection_get_setting_infiniband (connection);
		int p_key, parent_ifindex;

		parent_ifindex = nm_device_get_ifindex (parent);
		p_key = nm_setting_infiniband_get_p_key (s_infiniband);

		if (   !nm_platform_infiniband_partition_add (parent_ifindex, p_key)
		    && nm_platform_get_error () != NM_PLATFORM_ERROR_EXISTS) {
			nm_log_warn (LOGD_DEVICE, "(%s): failed to add InfiniBand P_Key interface for '%s'",
			             iface, nm_connection_get_id (connection));
			goto unblock;
		}

		device = nm_device_infiniband_new_partition (iface, nm_device_get_driver (parent));
	}

	if (device)
		add_device (self, device);

unblock:
	g_signal_handlers_unblock_by_func (nm_platform_get (), G_CALLBACK (platform_link_added_cb), self);

out:
	g_free (iface);
	return device;
}

static void
system_create_virtual_devices (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter, *connections;

	nm_log_dbg (LOGD_CORE, "creating virtual devices...");

	connections = nm_settings_get_connections (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = iter->data;
		NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);

		g_assert (s_con);
		if (connection_needs_virtual_device (connection)) {
			/* We only create a virtual interface if the connection can autoconnect */
			if (nm_setting_connection_get_autoconnect (s_con))
				system_create_virtual_device (self, connection);
		}
	}
	g_slist_free (connections);
}

static void
connection_added (NMSettings *settings,
                  NMSettingsConnection *settings_connection,
                  NMManager *manager)
{
	NMConnection *connection = NM_CONNECTION (settings_connection);

	if (connection_needs_virtual_device (connection)) {
		NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);

		g_assert (s_con);
		if (nm_setting_connection_get_autoconnect (s_con))
			system_create_virtual_device (manager, connection);
	}
}

static void
connection_changed (NMSettings *settings,
                    NMSettingsConnection *connection,
                    NMManager *manager)
{
	/* FIXME: Some virtual devices may need to be updated in the future. */
}

static void
connection_removed (NMSettings *settings,
                    NMSettingsConnection *connection,
                    NMManager *manager)
{
	/*
	 * Do not delete existing virtual devices to keep connectivity up.
	 * Virtual devices are reused when NetworkManager is restarted.
	 */
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

		managed = !nm_device_spec_match_list (device, unmanaged_specs);
		nm_device_set_manager_managed (device,
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
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_get_rfkill_type (device) == rstate->rtype) {
			nm_log_dbg (LOGD_RFKILL, "(%s): setting radio %s",
			            nm_device_get_iface (device),
			            enabled ? "enabled" : "disabled");
			nm_device_set_enabled (device, enabled);
		}
	}
}

static void
manager_hidden_ap_found (NMDevice *device,
                         NMAccessPoint *ap,
                         gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	const struct ether_addr *bssid;
	GSList *iter;
	GSList *connections;
	gboolean done = FALSE;

	g_return_if_fail (nm_ap_get_ssid (ap) == NULL);

	bssid = nm_ap_get_address (ap);
	g_assert (bssid);

	/* Look for this AP's BSSID in the seen-bssids list of a connection,
	 * and if a match is found, copy over the SSID */
	connections = nm_settings_get_connections (priv->settings);
	for (iter = connections; iter && !done; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingWireless *s_wifi;

		s_wifi = nm_connection_get_setting_wireless (connection);
		if (s_wifi) {
			if (nm_settings_connection_has_seen_bssid (NM_SETTINGS_CONNECTION (connection), bssid))
				nm_ap_set_ssid (ap, nm_setting_wireless_get_ssid (s_wifi));
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

		if (nm_device_get_device_type (candidate) == NM_DEVICE_TYPE_WIFI) {
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

		if (nm_device_get_rfkill_type (candidate) == RFKILL_TYPE_WWAN) {
			if (!nm_device_get_enabled (candidate))
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

	udev_state = nm_rfkill_manager_get_rfkill_state (priv->rfkill_mgr, rtype);

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
manager_modem_enabled_changed (NMDevice *device, gpointer user_data)
{
	nm_manager_rfkill_update (NM_MANAGER (user_data), RFKILL_TYPE_WWAN);
}

static void
device_auth_done_cb (NMAuthChain *chain,
                     GError *auth_error,
                     DBusGMethodInvocation *context,
                     gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthCallResult result;
	NMDevice *device;
	const char *permission;
	NMDeviceAuthRequestFunc callback;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	permission = nm_auth_chain_get_data (chain, "requested-permission");
	g_assert (permission);
	callback = nm_auth_chain_get_data (chain, "callback");
	g_assert (callback);
	device = nm_auth_chain_get_data (chain, "device");
	g_assert (device);

	result = nm_auth_chain_get_result (chain, permission);

	if (auth_error) {
		/* translate the auth error into a manager permission denied error */
		nm_log_dbg (LOGD_CORE, "%s request failed: %s", permission, auth_error->message);
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "%s request failed: %s",
		                     permission, auth_error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		nm_log_dbg (LOGD_CORE, "%s request failed: not authorized", permission);
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "%s request failed: not authorized",
		                     permission);
	}

	g_assert (error || (result == NM_AUTH_CALL_RESULT_YES));

	callback (device,
	          context,
	          error,
	          nm_auth_chain_get_data (chain, "user-data"));

	g_clear_error (&error);
	nm_auth_chain_unref (chain);
}

static void
device_auth_request_cb (NMDevice *device,
                        DBusGMethodInvocation *context,
                        const char *permission,
                        gboolean allow_interaction,
                        NMDeviceAuthRequestFunc callback,
                        gpointer user_data,
                        NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthChain *chain;
	const char *error_desc = NULL;

	/* Validate the request */
	chain = nm_auth_chain_new (context, device_auth_done_cb, self, &error_desc);
	if (chain) {
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);

		nm_auth_chain_set_data (chain, "device", g_object_ref (device), g_object_unref);
		nm_auth_chain_set_data (chain, "requested-permission", g_strdup (permission), g_free);
		nm_auth_chain_set_data (chain, "callback", callback, NULL);
		nm_auth_chain_set_data (chain, "user-data", user_data, NULL);
		nm_auth_chain_add_call (chain, permission, allow_interaction);
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		callback (device, context, error, user_data);
		g_error_free (error);
	}
}

/* This should really be moved to gsystem. */
#define free_slist __attribute__ ((cleanup(local_slist_free)))
static void
local_slist_free (void *loc)
{
	GSList **location = loc;

	if (location)
		g_slist_free (*location);
}

/**
 * get_connection:
 * @manager: #NMManager instance
 * @device: #NMDevice instance
 * @existing: is set to %TRUE when an existing connection was returned
 *
 * Returns one of the following:
 *
 * 1) An existing connection to be assumed.
 *
 * 2) A generated connection to be assumed.
 *
 * 3) %NULL when none of the above is available.
 *
 * Supports both nm-device's match_l2_config() and update_connection().
 */
static NMConnection *
get_connection (NMManager *manager, NMDevice *device, gboolean *existing)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	free_slist GSList *connections = nm_settings_get_connections (priv->settings);
	NMConnection *connection = NULL;
	GSList *iter;

	if (existing)
		*existing = FALSE;

	/* We still support the older API to match a NMDevice object to an
	 * existing connection using nm_device_find_assumable_connection().
	 *
	 * When the older API is still available for a particular device
	 * type, we use it. To opt for the newer interface, the NMDevice
	 * subclass must omit the match_l2_config virtual function
	 * implementation.
	 */
	if (NM_DEVICE_GET_CLASS (device)->match_l2_config) {
		NMConnection *candidate = nm_device_find_assumable_connection (device, connections);

		if (candidate) {
			nm_log_info (LOGD_DEVICE, "(%s): Found matching connection '%s' (legacy API)",
			            nm_device_get_iface (device),
			            nm_connection_get_id (candidate));
			if (existing)
				*existing = TRUE;
			return candidate;
		}
	}

	/* The core of the API is nm_device_generate_connection() function and
	 * update_connection() virtual method and the convenient connection_type
	 * class attribute. Subclasses supporting the new API must have
	 * update_connection() implemented, otherwise nm_device_generate_connection()
	 * returns NULL.
	 */
	connection = nm_device_generate_connection (device);
	if (!connection) {
		nm_log_info (LOGD_DEVICE, "(%s): No existing connection detected.",
		             nm_device_get_iface (device));
		return NULL;
	}

	/* Now we need to compare the generated connection to each configured
	 * connection. The comparison function is the heart of the connection
	 * assumption implementation and it must compare the connections very
	 * carefully to sort out various corner cases. Also, the comparison is
	 * not entirely symmetric.
	 *
	 * When no configured connection matches the generated connection, we keep
	 * the generated connection instead.
	 */
	for (iter = connections; iter; iter = iter->next) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		if (nm_connection_compare (connection, candidate, NM_SETTING_COMPARE_FLAG_CANDIDATE)) {
			nm_log_info (LOGD_DEVICE, "(%s): Found matching connection: '%s'",
						 nm_device_get_iface (device),
						 nm_connection_get_id (candidate));
			g_object_unref (connection);
			if (existing)
				*existing = TRUE;
			return candidate;
		}
	}

	nm_log_info (LOGD_DEVICE, "(%s): Using generated connection: '%s'",
				 nm_device_get_iface (device),
				 nm_connection_get_id (connection));
	return connection;
}

static void
add_device (NMManager *self, NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const char *iface, *driver, *type_desc;
	char *path;
	static guint32 devcount = 0;
	const GSList *unmanaged_specs;
	NMConnection *connection;
	gboolean enabled = FALSE;
	RfKillType rtype;
	NMDeviceType devtype;

	iface = nm_device_get_ip_iface (device);
	g_assert (iface);

	devtype = nm_device_get_device_type (device);

	/* Ignore the device if we already know about it.  But some modems will
	 * provide pseudo-ethernet devices that NM has already claimed while
	 * ModemManager is still detecting the modem's serial ports, so when the
	 * MM modem object finally shows up it may have the same IP interface as the
	 * ethernet interface we've already detected.  In this case we skip the
	 * check for an existing device with the same IP interface name and kill
	 * the ethernet device later in favor of the modem device.
	 */
	if ((devtype != NM_DEVICE_TYPE_MODEM) && find_device_by_ip_iface (self, iface)) {
		g_object_unref (device);
		return;
	}

	nm_device_set_connection_provider (device, NM_CONNECTION_PROVIDER (priv->settings));

	priv->devices = g_slist_append (priv->devices, device);

	g_signal_connect (device, "state-changed",
					  G_CALLBACK (manager_device_state_changed),
					  self);

	g_signal_connect (device, NM_DEVICE_AUTH_REQUEST,
	                  G_CALLBACK (device_auth_request_cb),
	                  self);

	if (priv->startup) {
		g_signal_connect (device, "notify::" NM_DEVICE_HAS_PENDING_ACTION,
		                  G_CALLBACK (device_has_pending_action_changed),
		                  self);
	}

	if (devtype == NM_DEVICE_TYPE_WIFI) {
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
	} else if (devtype == NM_DEVICE_TYPE_MODEM) {
		g_signal_connect (device, NM_DEVICE_MODEM_ENABLE_CHANGED,
		                  G_CALLBACK (manager_modem_enabled_changed),
		                  self);
	}

	/* Update global rfkill state for this device type with the device's
	 * rfkill state, and then set this device's rfkill state based on the
	 * global state.
	 */
	rtype = nm_device_get_rfkill_type (device);
	if (rtype != RFKILL_TYPE_UNKNOWN) {
		nm_manager_rfkill_update (self, rtype);
		enabled = radio_enabled_for_type (self, rtype, TRUE);
		nm_device_set_enabled (device, enabled);
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
	nm_dbus_manager_register_object (priv->dbus_mgr, path, device);
	nm_log_info (LOGD_CORE, "(%s): exported as %s", iface, path);
	g_free (path);

	connection = get_connection (self, device, NULL);

	/* Start the device if it's supposed to be managed */
	unmanaged_specs = nm_settings_get_unmanaged_specs (priv->settings);
	if (   !manager_sleeping (self)
	    && !nm_device_spec_match_list (device, unmanaged_specs)) {
		nm_device_set_manager_managed (device,
		                               TRUE,
		                               connection ? NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED :
		                                          NM_DEVICE_STATE_REASON_NOW_MANAGED);
	}

	nm_settings_device_added (priv->settings, device);
	g_signal_emit (self, signals[DEVICE_ADDED], 0, device);

	/* New devices might be master interfaces for virtual interfaces; so we may
	 * need to create new virtual interfaces now.
	 */
	system_create_virtual_devices (self);

	/* If the device has a connection it can assume, do that now */
	if (connection && nm_device_can_activate (device, connection)) {
		NMActiveConnection *ac;
		GError *error = NULL;

		nm_log_dbg (LOGD_DEVICE, "(%s): will attempt to assume connection",
		            nm_device_get_iface (device));

		ac = internal_activate_device (self, device, connection, NULL, FALSE, 0, NULL, TRUE, NULL, &error);
		if (ac)
			active_connection_add (self, ac);
		else {
			nm_log_warn (LOGD_DEVICE, "assumed connection %s failed to activate: (%d) %s",
			             nm_connection_get_path (connection),
			             error ? error->code : -1,
			             error && error->message ? error->message : "(unknown)");
			g_error_free (error);
		}
	}
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

	device = nm_device_bt_new (object_path, bdaddr, name, capabilities);
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
	NMDevice *device;

	g_return_if_fail (bdaddr != NULL);
	g_return_if_fail (object_path != NULL);

	device = nm_manager_get_device_by_udi (self, object_path);
	if (device) {
		nm_log_info (LOGD_HW, "BT device %s removed", bdaddr);
		remove_device (self, device, FALSE);
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
find_device_by_iface (NMManager *self, const gchar *iface)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = iter->data;

		if (g_strcmp0 (nm_device_get_iface (candidate), iface) == 0)
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

#define PLUGIN_PREFIX "libnm-device-plugin-"

typedef struct {
	NMDeviceType t;
	guint priority;
	NMDeviceFactoryCreateFunc create_func;
} PluginInfo;

static gint
plugin_sort (PluginInfo *a, PluginInfo *b)
{
	/* Higher priority means sort earlier in the list (ie, return -1) */
	if (a->priority > b->priority)
		return -1;
	else if (a->priority < b->priority)
		return 1;
	return 0;
}

static void
load_device_factories (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GDir *dir;
	GError *error = NULL;
	const char *item;
	char *path;
	GSList *list = NULL, *iter;

	dir = g_dir_open (NMPLUGINDIR, 0, &error);
	if (!dir) {
		nm_log_warn (LOGD_HW, "Failed to open plugin directory %s: %s",
		             NMPLUGINDIR,
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
		return;
	}

	while ((item = g_dir_read_name (dir))) {
		GModule *plugin;
		NMDeviceFactoryCreateFunc create_func;
		NMDeviceFactoryPriorityFunc priority_func;
		NMDeviceFactoryTypeFunc type_func;
		PluginInfo *info = NULL;
		NMDeviceType plugin_type;

		if (!g_str_has_prefix (item, PLUGIN_PREFIX))
			continue;

		path = g_module_build_path (NMPLUGINDIR, item);
		g_assert (path);
		plugin = g_module_open (path, G_MODULE_BIND_LOCAL);
		g_free (path);

		if (!plugin) {
			nm_log_warn (LOGD_HW, "(%s): failed to load plugin: %s", item, g_module_error ());
			continue;
		}

		if (!g_module_symbol (plugin, "nm_device_factory_get_type", (gpointer) (&type_func))) {
			nm_log_warn (LOGD_HW, "(%s): failed to find device factory: %s", item, g_module_error ());
			g_module_close (plugin);
			continue;
		}

		/* Make sure we don't double-load plugins */
		plugin_type = type_func ();
		for (iter = list; iter; iter = g_slist_next (iter)) {
			PluginInfo *candidate = iter->data;

			if (plugin_type == candidate->t) {
				info = candidate;
				break;
			}
		}
		if (info) {
			g_module_close (plugin);
			continue;
		}

		if (!g_module_symbol (plugin, "nm_device_factory_create_device", (gpointer) (&create_func))) {
			nm_log_warn (LOGD_HW, "(%s): failed to find device creator: %s", item, g_module_error ());
			g_module_close (plugin);
			continue;
		}

		info = g_malloc0 (sizeof (*info));
		info->create_func = create_func;
		info->t = plugin_type;

		/* Grab priority; higher number equals higher priority */
		if (g_module_symbol (plugin, "nm_device_factory_get_priority", (gpointer) (&priority_func)))
			info->priority = priority_func ();
		else {
			nm_log_dbg (LOGD_HW, "(%s): failed to find device factory priority func: %s",
			            item, g_module_error ());
		}

		g_module_make_resident (plugin);
		list = g_slist_insert_sorted (list, info, (GCompareFunc) plugin_sort);

		nm_log_info (LOGD_HW, "Loaded device factory: %s", g_module_name (plugin));
	};
	g_dir_close (dir);

	/* Ditch the priority info and copy the factory functions to our private data */
	for (iter = list; iter; iter = g_slist_next (iter)) {
		PluginInfo *info = iter->data;

		priv->factories = g_slist_append (priv->factories, info->create_func);
		g_free (info);
	}
	g_slist_free (list);
}

static void
platform_link_added_cb (NMPlatform *platform,
                        int ifindex,
                        NMPlatformLink *link,
                        NMPlatformReason reason,
                        gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *device = NULL;
	GSList *iter;
	GError *error = NULL;

	g_return_if_fail (ifindex > 0);

	if (find_device_by_ifindex (self, ifindex))
		return;

	/* Try registered device factories */
	for (iter = priv->factories; iter; iter = g_slist_next (iter)) {
		NMDeviceFactoryCreateFunc create_func = iter->data;

		g_clear_error (&error);
		device = (NMDevice *) create_func (link, &error);
		if (device && NM_IS_DEVICE (device)) {
			g_assert_no_error (error);
			break;  /* success! */
		}

		if (error) {
			nm_log_warn (LOGD_HW, "%s: factory failed to create device: (%d) %s",
			             link->udi,
			             error ? error->code : -1,
			             error ? error->message : "(unknown)");
			g_clear_error (&error);
			return;
		}
	}

	if (device == NULL) {
		int parent_ifindex = -1;
		NMDevice *parent;

		switch (link->type) {
		case NM_LINK_TYPE_ETHERNET:
			device = nm_device_ethernet_new (link);
			break;
		case NM_LINK_TYPE_INFINIBAND:
			device = nm_device_infiniband_new (link);
			break;
		case NM_LINK_TYPE_OLPC_MESH:
			device = nm_device_olpc_mesh_new (link);
			break;
		case NM_LINK_TYPE_WIFI:
			device = nm_device_wifi_new (link);
			break;
		case NM_LINK_TYPE_BOND:
			device = nm_device_bond_new (link->name);
			break;
		case NM_LINK_TYPE_TEAM:
			device = nm_device_team_new (link->name);
			break;
		case NM_LINK_TYPE_BRIDGE:
			/* FIXME: always create device when we handle bridges non-destructively */
			if (bridge_created_by_nm (self, link->name))
				device = nm_device_bridge_new (link->name);
			else
				nm_log_info (LOGD_BRIDGE, "(%s): ignoring bridge not created by NetworkManager", link->name);
			break;
		case NM_LINK_TYPE_VLAN:
			/* Have to find the parent device */
			if (nm_platform_vlan_get_info (ifindex, &parent_ifindex, NULL)) {
				parent = find_device_by_ifindex (self, parent_ifindex);
				if (parent)
					device = nm_device_vlan_new (link->name, parent);
				else {
					/* If udev signaled the VLAN interface before it signaled
					 * the VLAN's parent at startup we may not know about the
					 * parent device yet.  But we'll find it on the second pass
					 * from nm_manager_start().
					 */
					nm_log_dbg (LOGD_HW, "(%s): VLAN parent interface unknown", link->name);
				}
			} else
				nm_log_err (LOGD_HW, "(%s): failed to get VLAN parent ifindex", link->name);
			break;
		case NM_LINK_TYPE_VETH:
			device = nm_device_veth_new (link);
			break;
		case NM_LINK_TYPE_TUN:
		case NM_LINK_TYPE_TAP:
			device = nm_device_tun_new (link);
			break;
		case NM_LINK_TYPE_MACVLAN:
		case NM_LINK_TYPE_MACVTAP:
			device = nm_device_macvlan_new (link);
			break;
		case NM_LINK_TYPE_GRE:
		case NM_LINK_TYPE_GRETAP:
			device = nm_device_gre_new (link);
			break;

		case NM_LINK_TYPE_WWAN_ETHERNET:
			/* WWAN pseudo-ethernet interfaces are handled automatically by
			 * their NMDeviceModem and don't get a separate NMDevice object.
			 */
			break;

		default:
			device = nm_device_generic_new (link);
			break;
		}
	}

	if (device)
		add_device (self, device);
}

static void
platform_link_removed_cb (NMPlatform *platform,
                          int ifindex,
                          NMPlatformLink *link,
                          NMPlatformReason reason,
                          gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMDevice *device;

	device = find_device_by_ifindex (self, ifindex);
	if (device)
		remove_device (self, device, FALSE);
}

static void
atm_device_added_cb (NMAtmManager *atm_mgr,
                     const char *iface,
                     const char *sysfs_path,
                     const char *driver,
                     gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMDevice *device;

	g_return_if_fail (iface != NULL);
	g_return_if_fail (sysfs_path != NULL);

	device = find_device_by_iface (self, iface);
	if (device)
		return;

	device = nm_device_adsl_new (sysfs_path, iface, driver);
	if (device)
		add_device (self, device);
}

static void
atm_device_removed_cb (NMAtmManager *manager,
                       const char *iface,
                       gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *device = NULL;
	GSList *iter;

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (nm_device_get_iface (NM_DEVICE (iter->data)), iface) == 0) {
			device = iter->data;
			break;
		}
	}

	if (device)
		remove_device (self, device, FALSE);
}

static void
rfkill_manager_rfkill_changed_cb (NMRfkillManager *rfkill_mgr,
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

static NMActiveConnection *
internal_activate_device (NMManager *manager,
                          NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          gboolean user_requested,
                          gulong sender_uid,
                          const char *dbus_sender,
                          gboolean assumed,
                          NMActiveConnection *master,
                          GError **error)
{
	NMActRequest *req;
	NMDevice *master_device = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	/* Ensure the requested connection is compatible with the device */
	if (!nm_device_check_connection_compatible (device, connection, error))
		return NULL;

	/* Tear down any existing connection */
	if (nm_device_get_act_request (device)) {
		nm_log_info (LOGD_DEVICE, "(%s): disconnecting for new activation request.",
		             nm_device_get_iface (device));
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_NONE);
	}

	if (master)
		master_device = nm_active_connection_get_device (master);

	req = nm_act_request_new (connection,
	                          specific_object,
	                          user_requested,
	                          sender_uid,
	                          dbus_sender,
	                          device,
	                          master_device);
	g_assert (req);
	nm_device_activate (device, req);

	return NM_ACTIVE_CONNECTION (req);
}

/**
 * find_master:
 * @self: #NMManager object
 * @connection: the #NMConnection to find the master connection and device for
 * @device: the #NMDevice, if any, which will activate @connection
 * @out_master_connection: on success, the master connection of @connection if
 *   that master connection was found
 * @out_master_device: on success, the master device of @connection if that
 *   master device was found
 *
 * Given an #NMConnection, attempts to find its master connection and/or its
 * master device.  This function may return a master connection, a master device,
 * or both.  If only a connection is returned, that master connection is not
 * currently active on any device.  If only a device is returned, that device
 * is not currently activated with any connection.  If both are returned, then
 * the device is currently activated or activating with the returned master
 * connection.
 *
 * Returns: %TRUE if the master device and/or connection could be found or if
 *  the connection did not require a master, %FALSE otherwise
 **/
static gboolean
find_master (NMManager *self,
             NMConnection *connection,
             NMDevice *device,
             NMConnection **out_master_connection,
             NMDevice **out_master_device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *master;
	NMDevice *master_device = NULL;
	NMConnection *master_connection = NULL;
	GSList *iter, *connections = NULL;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	master = nm_setting_connection_get_master (s_con);

	if (master == NULL)
		return TRUE;  /* success, but no master */

	/* Try as an interface name first */
	master_device = find_device_by_ip_iface (self, master);
	if (master_device) {
		/* A device obviously can't be its own master */
		if (master_device == device)
			return FALSE;
	} else {
		/* Try master as a connection UUID */
		master_connection = (NMConnection *) nm_settings_get_connection_by_uuid (priv->settings, master);
		if (master_connection) {
			/* Check if the master connection is activated on some device already */
			for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
				NMDevice *candidate = NM_DEVICE (iter->data);

				if (candidate == device)
					continue;

				if (nm_device_get_connection (candidate) == master_connection) {
					master_device = candidate;
					break;
				}
			}
		} else {
			/* Might be a virtual interface that hasn't been created yet, so
			 * look through the interface names of connections that require
			 * virtual interfaces and see if one of their virtual interface
			 * names matches the master.
			 */
			connections = nm_settings_get_connections (priv->settings);
			for (iter = connections; iter && !master_connection; iter = g_slist_next (iter)) {
				NMConnection *candidate = iter->data;
				char *vname;

				if (connection_needs_virtual_device (candidate)) {
					vname = get_virtual_iface_name (self, candidate, NULL);
					if (g_strcmp0 (master, vname) == 0)
						master_connection = candidate;
					g_free (vname);
				}
			}
			g_slist_free (connections);
		}
	}

	if (out_master_connection)
		*out_master_connection = master_connection;
	if (out_master_device)
		*out_master_device = master_device;

    return master_device || master_connection;
}

static gboolean
is_compatible_with_slave (NMConnection *master, NMConnection *slave)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (master, FALSE);
	g_return_val_if_fail (slave, FALSE);

	s_con = nm_connection_get_setting_connection (slave);
	g_assert (s_con);

	return nm_connection_is_type (master, nm_setting_connection_get_slave_type (s_con));
}

/**
 * ensure_master_active_connection:
 *
 * @self: the #NMManager
 * @dbus_sender: if the request was initiated by a user via D-Bus, the
 *   dbus sender name of the client that requested the activation; for auto
 *   activated connections use %NULL
 * @connection: the connection that should depend on @master_connection
 * @device: the #NMDevice, if any, which will activate @connection
 * @master_connection: the master connection
 * @master_device: the master device
 * @error: the error, if an error occurred
 *
 * Determines whether a given #NMConnection depends on another connection to
 * be activated, and if so, finds that master connection or creates it.
 *
 * Returns: the master #NMActiveConnection that the caller should depend on, or
 * %NULL if an error occurred
 */
static NMActiveConnection *
ensure_master_active_connection (NMManager *self,
                                 const char *dbus_sender,
                                 NMConnection *connection,
                                 NMDevice *device,
                                 NMConnection *master_connection,
                                 NMDevice *master_device,
                                 GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *master_ac = NULL;
	NMDeviceState master_state;
	GSList *iter;

	g_assert (connection);
	g_assert (master_connection || master_device);

	/* If the master device isn't activated then we need to activate it using
	 * compatible connection.  If it's already activating we can just proceed.
	 */
	if (master_device) {
		/* If we're passed a connection and a device, we require that connection
		 * be already activated on the device, eg returned from find_master().
		 */
		if (master_connection)
			g_assert (nm_device_get_connection (master_device) == master_connection);

		master_state = nm_device_get_state (master_device);
		if (   (master_state == NM_DEVICE_STATE_ACTIVATED)
		    || nm_device_is_activating (master_device)) {
			/* Device already using master_connection */
			return NM_ACTIVE_CONNECTION (nm_device_get_act_request (master_device));
		}

		/* If the device is disconnected, find a compabile connection and
		 * activate it on the device.
		 */
		if (master_state == NM_DEVICE_STATE_DISCONNECTED) {
			GSList *connections;

			g_assert (master_connection == NULL);

			/* Find a compatible connection and activate this device using it */
			connections = nm_settings_get_connections (priv->settings);
			for (iter = connections; iter; iter = g_slist_next (iter)) {
				NMConnection *candidate = NM_CONNECTION (iter->data);

				/* Ensure eg bond/team slave and the candidate master is a
				 * bond/team master
				 */
				if (!is_compatible_with_slave (candidate, connection))
					continue;

				if (nm_device_check_connection_compatible (master_device, candidate, NULL)) {
					master_ac = nm_manager_activate_connection (self,
					                                            candidate,
					                                            NULL,
					                                            nm_device_get_path (master_device),
					                                            dbus_sender,
					                                            error);
					if (!master_ac)
						g_prefix_error (error, "%s", "Master device activation failed: ");
					g_slist_free (connections);
					return master_ac;
				}
			}
			g_slist_free (connections);

			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
			             "No compatible connection found for master device %s.",
			             nm_device_get_iface (master_device));
			return NULL;
		}

		/* Otherwise, the device is unmanaged, unavailable, or disconnecting */
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_UNMANAGED_DEVICE,
		             "Master device %s unmanaged or not available for activation",
		             nm_device_get_iface (master_device));
	} else if (master_connection) {
		gboolean found_device = FALSE;

		/* Find a compatible device and activate it using this connection */
		for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
			NMDevice *candidate = NM_DEVICE (iter->data);

			if (candidate == device) {
				/* A device obviously can't be its own master */
				continue;
			}

			if (!nm_device_check_connection_compatible (candidate, master_connection, NULL))
				continue;

			found_device = TRUE;
			master_state = nm_device_get_state (candidate);
			if (master_state != NM_DEVICE_STATE_DISCONNECTED)
				continue;

			master_ac = nm_manager_activate_connection (self,
			                                            master_connection,
			                                            NULL,
			                                            nm_device_get_path (candidate),
			                                            dbus_sender,
			                                            error);
			if (!master_ac)
				g_prefix_error (error, "%s", "Master device activation failed: ");
			return master_ac;
		}

		/* Device described by master_connection may be a virtual one that's
		 * not created yet.
		 */
		if (!found_device && connection_needs_virtual_device (master_connection)) {
			master_ac = nm_manager_activate_connection (self,
			                                            master_connection,
			                                            NULL,
			                                            NULL,
			                                            dbus_sender,
			                                            error);
			if (!master_ac)
				g_prefix_error (error, "%s", "Master device activation failed: ");
			return master_ac;
		}

		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		             "No compatible disconnected device found for master connection %s.",
		             nm_connection_get_uuid (master_connection));
	} else
		g_assert_not_reached ();

	return NULL;
}

static NMActiveConnection *
activate_vpn_connection (NMManager *self,
                         NMConnection *connection,
                         const char *specific_object,
                         gulong sender_uid,
                         GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *parent = NULL;
	NMDevice *device = NULL;
	GSList *iter;

	if (specific_object) {
		/* Find the specifc connection the client requested we use */
		parent = active_connection_get_by_path (self, specific_object);
		if (!parent) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
			                     "Base connection for VPN connection not active.");
			return NULL;
		}
	} else {
		for (iter = priv->active_connections; iter; iter = g_slist_next (iter)) {
			NMActiveConnection *candidate = iter->data;

			if (nm_active_connection_get_default (candidate)) {
				parent = candidate;
				break;
			}
		}
	}

	if (!parent) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                     "Could not find source connection.");
		return NULL;
	}

	device = nm_active_connection_get_device (parent);
	if (!device) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		                     "Source connection had no active device.");
		return NULL;
	}

	return nm_vpn_manager_activate_connection (priv->vpn_manager,
	                                           connection,
	                                           device,
	                                           nm_active_connection_get_path (parent),
	                                           TRUE,
	                                           sender_uid,
	                                           error);
}

NMActiveConnection *
nm_manager_activate_connection (NMManager *manager,
                                NMConnection *connection,
                                const char *specific_object,
                                const char *device_path,
                                const char *dbus_sender,
                                GError **error)
{
	NMManagerPrivate *priv;
	NMDevice *device = NULL;
	gulong sender_uid = G_MAXULONG;
	char *iface;
	NMDevice *master_device = NULL;
	NMConnection *master_connection = NULL;
	NMActiveConnection *master_ac = NULL, *ac = NULL;
	gboolean matched;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);

	/* Get the UID of the user that originated the request, if any */
	if (dbus_sender) {
		if (!nm_dbus_manager_get_unix_user (priv->dbus_mgr, dbus_sender, &sender_uid)) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR, NM_MANAGER_ERROR_PERMISSION_DENIED,
			                     "Failed to get unix user for dbus sender");
			return NULL;
		}
	} else {
		/* No sender means an internal/automatic activation request */
		sender_uid = 0;
	}

	/* VPN ? */
	if (nm_connection_is_type (connection, NM_SETTING_VPN_SETTING_NAME)) {
		ac = activate_vpn_connection (manager, connection, specific_object, sender_uid, error);
		goto activated;
	}

	/* Device-based connection */
	if (device_path) {
		device = nm_manager_get_device_by_path (manager, device_path);
		if (!device) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                     "Device not found");
			return NULL;
		}

		/* If it's a virtual interface make sure the device given by the
		 * path matches the connection's interface details.
		 */
		if (connection_needs_virtual_device (connection)) {
			iface = get_virtual_iface_name (manager, connection, NULL);
			if (!iface) {
				g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
					                 "Failed to determine connection's virtual interface name");
				return NULL;
			}

			matched = g_str_equal (iface, nm_device_get_ip_iface (device));
			g_free (iface);
			if (!matched) {
				g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
					                 "Device given by path did not match connection's virtual interface name");
				return NULL;
			}
		}
	} else {
		/* Virtual connections (VLAN, bond, team, etc) may not specify
		 * a device path because the device may not be created yet,
		 * or it be given by the connection's properties instead.
		 * Find the device the connection refers to, or create it
		 * if needed.
		 */
		if (!connection_needs_virtual_device (connection)) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
				                 "This connection requires an existing device.");
			return NULL;
		}

		iface = get_virtual_iface_name (manager, connection, NULL);
		if (!iface) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
				                 "Failed to determine connection's virtual interface name");
			return NULL;
		}

		device = find_device_by_ip_iface (manager, iface);
		g_free (iface);
		if (!device) {
			/* Create it */
			device = system_create_virtual_device (manager, connection);
			if (!device) {
				g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
						             "Failed to create virtual interface");
				return NULL;
			}

			/* A newly created device, if allowed to be managed by NM, will be
			 * in the UNAVAILABLE state here.  To ensure it can be activated
			 * immediately, we transition it to DISCONNECTED so it passes the
			 * nm_device_can_activate() check below.
			 */
			if (   nm_device_is_available (device)
			    && (nm_device_get_state (device) == NM_DEVICE_STATE_UNAVAILABLE)) {
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_DISCONNECTED,
				                         NM_DEVICE_STATE_REASON_NONE);
			}
		}
	}

	if (!nm_device_can_activate (device, connection)) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNMANAGED_DEVICE,
			                 "Device not managed by NetworkManager or unavailable");
		return NULL;
	}

	/* If this is an autoconnect request, but the device isn't allowing autoconnect
	 * right now, we reject it.
	 */
	if (!dbus_sender && !nm_device_autoconnect_allowed (device)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_AUTOCONNECT_NOT_ALLOWED,
		             "%s does not allow automatic connections at this time",
		             nm_device_get_iface (device));
		return NULL;
	}

	/* Try to find the master connection/device if the connection has a dependency */
	if (!find_master (manager, connection, device, &master_connection, &master_device)) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                 "Master connection not found or invalid");
		return NULL;
	}

	/* Ensure there's a master active connection the new connection we're
	 * activating can depend on.
	 */
	if (master_connection || master_device) {
		if (master_connection) {
			nm_log_dbg (LOGD_CORE, "Activation of '%s' requires master connection '%s'",
			            nm_connection_get_id (connection),
			            nm_connection_get_id (master_connection));
		}
		if (master_device) {
			nm_log_dbg (LOGD_CORE, "Activation of '%s' requires master device '%s'",
			            nm_connection_get_id (connection),
			            nm_device_get_ip_iface (master_device));
		}

		/* Ensure eg bond/team slave and the candidate master is
		 * a bond/team master
		 */
		if (master_connection && !is_compatible_with_slave (master_connection, connection)) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
					             "The master connection was not compatible");
			return NULL;
		}

		master_ac = ensure_master_active_connection (manager,
		                                             dbus_sender,
		                                             connection,
		                                             device,
		                                             master_connection,
		                                             master_device,
		                                             error);
		if (!master_ac) {
			if (error)
				g_assert (*error);
			return NULL;
		}

		nm_log_dbg (LOGD_CORE, "Activation of '%s' depends on active connection %s",
		            nm_connection_get_id (connection),
		            nm_active_connection_get_path (master_ac));
	}

	ac = internal_activate_device (manager,
	                               device,
	                               connection,
	                               specific_object,
	                               dbus_sender ? TRUE : FALSE,
	                               dbus_sender ? sender_uid : 0,
	                               dbus_sender,
	                               FALSE,
	                               master_ac,
	                               error);

activated:
	if (ac)
		active_connection_add (manager, ac);

	return ac;
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
	NMActiveConnection *ac = NULL;
	GError *error = NULL;
	char *sender = NULL;

	/* Ok, we're authorized */

	connection = nm_settings_get_connection_by_path (priv->settings, pending->connection_path);
	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "Connection could not be found.");
		goto out;
	}

	if (!nm_dbus_manager_get_caller_info (priv->dbus_mgr,
	                                      pending->context,
	                                      &sender,
	                                      NULL)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "D-Bus sendder could not be determined.");
		goto out;
	}

	g_assert (sender);
	ac = nm_manager_activate_connection (self,
	                                     NM_CONNECTION (connection),
	                                     pending->specific_object_path,
	                                     pending->device_path,
	                                     sender,
	                                     &error);
	g_free (sender);

	if (!ac) {
		nm_log_warn (LOGD_CORE, "connection %s failed to activate: (%d) %s",
		             pending->connection_path,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
	}

out:
	pending_activation_destroy (pending, error, ac);
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
		pending_activation_check_authorized (pending);
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
		nm_settings_add_connection_dbus (priv->settings,
		                                 pending->connection,
		                                 TRUE,
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
		pending_activation_check_authorized (pending);
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
	NMActiveConnection *active;
	gboolean success = FALSE;

	active = active_connection_get_by_path (manager, connection_path);
	if (!active) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
		                     "The connection was not active.");
		return FALSE;
	}

	if (NM_IS_VPN_CONNECTION (active)) {
		NMVPNConnectionStateReason vpn_reason = NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED;

		if (reason == NM_DEVICE_STATE_REASON_CONNECTION_REMOVED)
			vpn_reason = NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED;
		if (nm_vpn_manager_deactivate_connection (priv->vpn_manager, NM_VPN_CONNECTION (active), vpn_reason))
			success = TRUE;
		else
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
			                     "The VPN connection was not active.");
	} else {
		g_assert (NM_IS_ACT_REQUEST (active));
		/* FIXME: use DEACTIVATING state */
		nm_device_state_changed (nm_active_connection_get_device (active),
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         reason);
		success = TRUE;
	}

	if (success)
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

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL);

	if (auth_error) {
		nm_log_dbg (LOGD_CORE, "Disconnect request failed: %s", auth_error->message);
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "Deactivate request failed: %s",
		                     auth_error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Not authorized to deactivate connections");
	} else {
		/* success; deactivation allowed */
		if (!nm_manager_deactivate_connection (self,
		                                       nm_auth_chain_get_data (chain, "path"),
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
	const char *error_desc = NULL;

	/* Find the connection by its object path */
	for (iter = priv->active_connections; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *ac = iter->data;

		if (g_strcmp0 (nm_active_connection_get_path (ac), active_path) == 0) {
			connection = nm_active_connection_get_connection (ac);
			break;
		}
	}

	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
		                             "The connection was not active.");
		dbus_g_method_return_error (context, error);
		g_error_free (error);
		return;
	}

	/* Validate the user request */
	chain = nm_auth_chain_new (context, deactivate_net_auth_done_cb, self, &error_desc);
	if (chain) {
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);

		nm_auth_chain_set_data (chain, "path", g_strdup (active_path), g_free);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
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
			nm_device_set_manager_managed (NM_DEVICE (iter->data), FALSE, NM_DEVICE_STATE_REASON_SLEEPING);

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

				if (rstate->desc) {
					nm_log_dbg (LOGD_RFKILL, "%s %s devices (hw_enabled %d, sw_enabled %d, user_enabled %d)",
					            enabled ? "enabling" : "disabling",
					            rstate->desc, rstate->hw_enabled, rstate->sw_enabled, rstate->user_enabled);
				}

				if (nm_device_get_rfkill_type (device) == rstate->rtype)
					nm_device_set_enabled (device, enabled);
			}

			g_object_set (G_OBJECT (device), NM_DEVICE_AUTOCONNECT, TRUE, NULL);

			if (nm_device_spec_match_list (device, unmanaged_specs))
				nm_device_set_manager_managed (device, FALSE, NM_DEVICE_STATE_REASON_NOW_UNMANAGED);
			else
				nm_device_set_manager_managed (device, TRUE, NM_DEVICE_STATE_REASON_NOW_MANAGED);
		}
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

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_SLEEP_WAKE);
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
	chain = nm_auth_chain_new (context, sleep_auth_done_cb, self, &error_desc);
	if (chain) {
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);
		nm_auth_chain_set_data (chain, "sleep", GUINT_TO_POINTER (do_sleep), NULL);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SLEEP_WAKE, TRUE);
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
#endif
}

static void
sleeping_cb (DBusGProxy *proxy, gpointer user_data)
{
	nm_log_dbg (LOGD_SUSPEND, "Received sleeping signal");
	_internal_sleep (NM_MANAGER (user_data), TRUE);
}

static void
resuming_cb (DBusGProxy *proxy, gpointer user_data)
{
	nm_log_dbg (LOGD_SUSPEND, "Received resuming signal");
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
	GError *ret_error = NULL;
	NMAuthCallResult result;
	gboolean enable;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK);
	if (error) {
		nm_log_dbg (LOGD_CORE, "Enable request failed: %s", error->message);
		ret_error = g_error_new (NM_MANAGER_ERROR,
		                         NM_MANAGER_ERROR_PERMISSION_DENIED,
		                         "Enable request failed: %s",
		                         error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		ret_error = g_error_new_literal (NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
		                                 "Not authorized to enable/disable networking");
	} else {
		/* Auth success */
		enable = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "enable"));
		_internal_enable (self, enable);
		dbus_g_method_return (context);
	}

	if (ret_error) {
		dbus_g_method_return_error (context, ret_error);
		g_error_free (ret_error);
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
	const char *error_desc;

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

	chain = nm_auth_chain_new (context, enable_net_done_cb, self, &error_desc);
	if (chain) {
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);

		nm_auth_chain_set_data (chain, "enable", GUINT_TO_POINTER (enable), NULL);
		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK, TRUE);
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
}

/* Permissions */

static void
get_perm_add_result (NMAuthChain *chain, GHashTable *results, const char *permission)
{
	NMAuthCallResult result;

	result = nm_auth_chain_get_result (chain, permission);
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
	const char *error_desc = NULL;
	GError *error;

	chain = nm_auth_chain_new (context, get_permissions_done_cb, self, &error_desc);
	if (chain) {
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
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
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

static void
impl_manager_get_logging (NMManager *manager,
                          char **level,
                          char **domains)
{
	*level = g_strdup (nm_logging_level_to_string ());
	*domains = g_strdup (nm_logging_domains_to_string ());
}

static void
connectivity_check_done (GObject *object,
                         GAsyncResult *result,
                         gpointer user_data)
{
	DBusGMethodInvocation *context = user_data;
	NMConnectivityState state;
	GError *error = NULL;

	state = nm_connectivity_check_finish (NM_CONNECTIVITY (object), result, &error);
	if (error) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	} else
		dbus_g_method_return (context, state);
}


static void
check_connectivity_auth_done_cb (NMAuthChain *chain,
                                 GError *auth_error,
                                 DBusGMethodInvocation *context,
                                 gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthCallResult result;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL);

	if (auth_error) {
		nm_log_dbg (LOGD_CORE, "CheckConnectivity request failed: %s", auth_error->message);
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "Connectivity check request failed: %s",
		                     auth_error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Not authorized to recheck connectivity");
	} else {
		/* it's allowed */
		nm_connectivity_check_async (priv->connectivity,
		                             connectivity_check_done,
		                             context);
	}

	if (error) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
	nm_auth_chain_unref (chain);
}

static void
impl_manager_check_connectivity (NMManager *manager,
                                 DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMAuthChain *chain;
	const char *error_desc = NULL;
	GError *error;

	/* Validate the user request */
	chain = nm_auth_chain_new (context, check_connectivity_auth_done_cb, manager, &error_desc);
	if (chain) {
		priv->auth_chains = g_slist_append (priv->auth_chains, chain);

		nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	}
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

		udev_state = nm_rfkill_manager_get_rfkill_state (priv->rfkill_mgr, i);
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

	/* FIXME: remove when we handle bridges non-destructively */
	/* Read a list of bridges NM managed when it last quit, and only
	 * manage those bridges to avoid conflicts with external tools.
	 */
	priv->nm_bridges = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	read_nm_created_bridges (self);

	nm_platform_query_devices ();
	nm_atm_manager_query_devices (priv->atm_mgr);
	nm_bluez_manager_query_devices (priv->bluez_mgr);

	/*
	 * Connections added before the manager is started do not emit
	 * connection-added signals thus devices have to be created manually.
	 */
	system_create_virtual_devices (self);

	/* FIXME: remove when we handle bridges non-destructively */
	g_hash_table_unref (priv->nm_bridges);
	priv->nm_bridges = NULL;

	check_if_startup_complete (self);
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
connectivity_changed (NMConnectivity *connectivity,
                      GParamSpec *pspec,
                      gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMConnectivityState state;
	static const char *connectivity_states[] = { "UNKNOWN", "NONE", "PORTAL", "LIMITED", "FULL" };

	state = nm_connectivity_get_state (connectivity);
	nm_log_dbg (LOGD_CORE, "connectivity checking indicates %s",
	            connectivity_states[state]);

	nm_manager_update_state (self);
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
	case G_FILE_MONITOR_EVENT_MOVED:
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

static void
policy_default_device_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *best;
	NMActiveConnection *ac;

	/* Note: this assumes that it's not possible for the IP4 default
	 * route to be going over the default-ip6-device. If that changes,
	 * we need something more complicated here.
	 */
	best = nm_policy_get_default_ip4_device (priv->policy);
	if (!best)
		best = nm_policy_get_default_ip6_device (priv->policy);

	if (best)
		ac = NM_ACTIVE_CONNECTION (nm_device_get_act_request (best));
	else
		ac = NULL;

	if (ac != priv->primary_connection) {
		g_clear_object (&priv->primary_connection);
		priv->primary_connection = ac ? g_object_ref (ac) : NULL;
		nm_log_dbg (LOGD_CORE, "PrimaryConnection now %s", ac ? nm_active_connection_get_name (ac) : "(none)");
		g_object_notify (G_OBJECT (self), NM_MANAGER_PRIMARY_CONNECTION);
	}
}

static void
policy_activating_device_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *activating, *best;
	NMActiveConnection *ac;

	/* We only look at activating-ip6-device if activating-ip4-device
	 * AND default-ip4-device are NULL; if default-ip4-device is
	 * non-NULL, then activating-ip6-device is irrelevant, since while
	 * that device might become the new default-ip6-device, it can't
	 * become primary-connection while default-ip4-device is set to
	 * something else.
	 */
	activating = nm_policy_get_activating_ip4_device (priv->policy);
	best = nm_policy_get_default_ip4_device (priv->policy);
	if (!activating && !best)
		activating = nm_policy_get_activating_ip6_device (priv->policy);

	if (activating)
		ac = NM_ACTIVE_CONNECTION (nm_device_get_act_request (activating));
	else
		ac = NULL;

	if (ac != priv->activating_connection) {
		g_clear_object (&priv->activating_connection);
		priv->activating_connection = ac ? g_object_ref (ac) : NULL;
		nm_log_dbg (LOGD_CORE, "ActivatingConnection now %s", ac ? nm_active_connection_get_name (ac) : "(none)");
		g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVATING_CONNECTION);
	}
}

#define NM_PERM_DENIED_ERROR "org.freedesktop.NetworkManager.PermissionDenied"
#define DEV_PERM_DENIED_ERROR "org.freedesktop.NetworkManager.Device.PermissionDenied"

static void
prop_set_auth_done_cb (NMAuthChain *chain,
                       GError *error,
                       DBusGMethodInvocation *context,
                       gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	DBusConnection *connection;
	NMAuthCallResult result;
	DBusMessage *reply = NULL, *message;
	const char *permission, *prop;
	GObject *obj;
	gboolean set_enabled = TRUE;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	message = nm_auth_chain_get_data (chain, "message");
	permission = nm_auth_chain_get_data (chain, "permission");
	prop = nm_auth_chain_get_data (chain, "prop");
	set_enabled = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "enabled"));
	obj = nm_auth_chain_get_data (chain, "object");

	result = nm_auth_chain_get_result (chain, permission);
	if (error || (result != NM_AUTH_CALL_RESULT_YES)) {
		reply = dbus_message_new_error (message,
		                                NM_IS_DEVICE (obj) ? DEV_PERM_DENIED_ERROR : NM_PERM_DENIED_ERROR,
		                                "Not authorized to perform this operation");
	} else {
		g_object_set (obj, prop, set_enabled, NULL);
		reply = dbus_message_new_method_return (message);
	}

	g_assert (reply);
	connection = nm_auth_chain_get_data (chain, "connection");
	g_assert (connection);
	dbus_connection_send (connection, reply, NULL);
	dbus_message_unref (reply);

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
	const char *glib_propname = NULL, *permission = NULL;
	gulong caller_uid = G_MAXULONG;
	DBusMessage *reply = NULL;
	gboolean set_enabled = FALSE;
	NMAuthChain *chain;
	GObject *obj;

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
	if (!propiface || (strcmp (propiface, NM_DBUS_INTERFACE) && strcmp (propiface, NM_DBUS_INTERFACE_DEVICE)))
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
	} else if (!strcmp (propname, "Autoconnect")) {
		glib_propname = NM_DEVICE_AUTOCONNECT;
		permission = NM_AUTH_PERMISSION_NETWORK_CONTROL;
	} else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	/* Get the new value for the property */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_VARIANT)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_message_iter_recurse (&iter, &sub);
	if (dbus_message_iter_get_arg_type (&sub) != DBUS_TYPE_BOOLEAN)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	dbus_message_iter_get_basic (&sub, &set_enabled);

	/* Make sure the object exists */
	obj = dbus_g_connection_lookup_g_object (dbus_connection_get_g_connection (connection),
	                                         dbus_message_get_path (message));
	if (!obj) {
		reply = dbus_message_new_error (message, NM_PERM_DENIED_ERROR,
		                                "Object does not exist");
		goto out;
	}

	if (!nm_dbus_manager_get_caller_info_from_message (priv->dbus_mgr,
	                                                   connection,
	                                                   message,
	                                                   NULL,
	                                                   &caller_uid)) {
		reply = dbus_message_new_error (message, NM_PERM_DENIED_ERROR,
		                                "Could not determine request UID.");
		goto out;
	}

	/* Validate the user request */
	chain = nm_auth_chain_new_raw_message (message, caller_uid, prop_set_auth_done_cb, self);
	g_assert (chain);
	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "prop", g_strdup (glib_propname), g_free);
	nm_auth_chain_set_data (chain, "permission", g_strdup (permission), g_free);
	nm_auth_chain_set_data (chain, "enabled", GUINT_TO_POINTER (set_enabled), NULL);
	nm_auth_chain_set_data (chain, "message", dbus_message_ref (message), (GDestroyNotify) dbus_message_unref);
	nm_auth_chain_set_data (chain, "connection", dbus_connection_ref (connection), (GDestroyNotify) dbus_connection_unref);
	nm_auth_chain_set_data (chain, "object", g_object_ref (obj), (GDestroyNotify) g_object_unref);
	nm_auth_chain_add_call (chain, permission, TRUE);

out:
	if (reply) {
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}
	return DBUS_HANDLER_RESULT_HANDLED;
}

static NMManager *singleton = NULL;

NMManager *
nm_manager_get (void)
{
	g_assert (singleton);
	return g_object_ref (singleton);
}

NMManager *
nm_manager_new (NMSettings *settings,
                const char *state_file,
                gboolean initial_net_enabled,
                gboolean initial_wifi_enabled,
                gboolean initial_wwan_enabled,
                gboolean initial_wimax_enabled,
                GError **error)
{
	NMManagerPrivate *priv;
	DBusGConnection *bus;
	DBusConnection *dbus_connection;

	g_assert (settings);

	/* Can only be called once */
	g_assert (singleton == NULL);
	singleton = (NMManager *) g_object_new (NM_TYPE_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_MANAGER_GET_PRIVATE (singleton);

	priv->policy = nm_policy_new (singleton, settings);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP4_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), singleton);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP6_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), singleton);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP4_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), singleton);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP6_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), singleton);

	priv->connectivity = nm_connectivity_new ();
	g_signal_connect (priv->connectivity, "notify::" NM_CONNECTIVITY_STATE,
	                  G_CALLBACK (connectivity_changed), singleton);

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
	                  G_CALLBACK (connection_added), singleton);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (connection_changed), singleton);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_REMOVED,
	                  G_CALLBACK (connection_removed), singleton);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_VISIBILITY_CHANGED,
	                  G_CALLBACK (connection_changed), singleton);

	nm_dbus_manager_register_object (priv->dbus_mgr, NM_DBUS_PATH, singleton);

	g_signal_connect (nm_platform_get (),
	                  NM_PLATFORM_LINK_ADDED,
	                  G_CALLBACK (platform_link_added_cb),
	                  singleton);
	g_signal_connect (nm_platform_get (),
	                  NM_PLATFORM_LINK_REMOVED,
	                  G_CALLBACK (platform_link_removed_cb),
	                  singleton);

	priv->atm_mgr = nm_atm_manager_new ();
	g_signal_connect (priv->atm_mgr,
	                  "device-added",
	                  G_CALLBACK (atm_device_added_cb),
	                  singleton);
	g_signal_connect (priv->atm_mgr,
	                  "device-removed",
	                  G_CALLBACK (atm_device_removed_cb),
	                  singleton);

	priv->rfkill_mgr = nm_rfkill_manager_new ();
	g_signal_connect (priv->rfkill_mgr,
	                  "rfkill-changed",
	                  G_CALLBACK (rfkill_manager_rfkill_changed_cb),
	                  singleton);

	priv->bluez_mgr = nm_bluez_manager_get (NM_CONNECTION_PROVIDER (priv->settings));

	g_signal_connect (priv->bluez_mgr,
	                  NM_BLUEZ_MANAGER_BDADDR_ADDED,
	                  G_CALLBACK (bluez_manager_bdaddr_added_cb),
	                  singleton);

	g_signal_connect (priv->bluez_mgr,
	                  NM_BLUEZ_MANAGER_BDADDR_REMOVED,
	                  G_CALLBACK (bluez_manager_bdaddr_removed_cb),
	                  singleton);

	/* Force kernel WiFi rfkill state to follow NM saved wifi state in case
	 * the BIOS doesn't save rfkill state, and to be consistent with user
	 * changes to the WirelessEnabled property which toggles kernel rfkill.
	 */
	rfkill_change_wifi (priv->radio_states[RFKILL_TYPE_WLAN].desc, initial_wifi_enabled);

	return singleton;
}

static void
authority_changed_cb (gpointer user_data)
{
	/* Let clients know they should re-check their authorization */
	g_signal_emit (NM_MANAGER (user_data), signals[CHECK_PERMISSIONS], 0);
}

static void
dispose (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *bus;
	DBusConnection *dbus_connection;
	GSList *iter;

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_slist_foreach (priv->auth_chains, (GFunc) nm_auth_chain_unref, NULL);
	g_slist_free (priv->auth_chains);

	nm_auth_changed_func_unregister (authority_changed_cb, manager);

	/* FIXME: remove when we handle bridges non-destructively */
	write_nm_created_bridges (manager);

	/* Remove all devices */
	while (priv->devices)
		remove_device (manager, NM_DEVICE (priv->devices->data), TRUE);

	if (priv->ac_cleanup_id) {
		g_source_remove (priv->ac_cleanup_id);
		priv->ac_cleanup_id = 0;
	}

	for (iter = priv->active_connections; iter; iter = g_slist_next (iter)) {
		g_signal_handlers_disconnect_by_func (iter->data, active_connection_state_changed, object);
		g_object_unref (iter->data);
	}
	g_slist_free (priv->active_connections);
	g_clear_object (&priv->primary_connection);
	g_clear_object (&priv->activating_connection);

	g_clear_object (&priv->connectivity);

	g_free (priv->hostname);

	g_signal_handlers_disconnect_by_func (priv->policy, G_CALLBACK (policy_default_device_changed), singleton);
	g_signal_handlers_disconnect_by_func (priv->policy, G_CALLBACK (policy_activating_device_changed), singleton);
	g_object_unref (priv->policy);

	g_object_unref (priv->settings);
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
	g_signal_handler_disconnect (priv->dbus_mgr, priv->dbus_connection_changed_id);
	priv->dbus_mgr = NULL;

	if (priv->bluez_mgr)
		g_object_unref (priv->bluez_mgr);

	if (priv->aipd_proxy)
		g_object_unref (priv->aipd_proxy);

	if (priv->sleep_monitor)
		g_object_unref (priv->sleep_monitor);

	if (priv->fw_monitor) {
		if (priv->fw_monitor_id)
			g_signal_handler_disconnect (priv->fw_monitor, priv->fw_monitor_id);

		if (priv->fw_changed_id)
			g_source_remove (priv->fw_changed_id);

		g_file_monitor_cancel (priv->fw_monitor);
		g_object_unref (priv->fw_monitor);
	}

	g_slist_free (priv->factories);

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
	GSList *iter;
	GPtrArray *active;
	const char *path;

	switch (prop_id) {
	case PROP_VERSION:
		g_value_set_string (value, VERSION);
		break;
	case PROP_STATE:
		nm_manager_update_state (self);
		g_value_set_uint (value, priv->state);
		break;
	case PROP_STARTUP:
		g_value_set_boolean (value, priv->startup);
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
		active = g_ptr_array_sized_new (3);
		for (iter = priv->active_connections; iter; iter = g_slist_next (iter)) {
			path = nm_active_connection_get_path (NM_ACTIVE_CONNECTION (iter->data));
			g_ptr_array_add (active, g_strdup (path));
		}
		g_value_take_boxed (value, active);
		break;
	case PROP_CONNECTIVITY:
		g_value_set_uint (value, nm_connectivity_get_state (priv->connectivity));
		break;
	case PROP_PRIMARY_CONNECTION:
		path = priv->primary_connection ? nm_active_connection_get_path (priv->primary_connection) : "/";
		g_value_set_boxed (value, path);
		break;
	case PROP_ACTIVATING_CONNECTION:
		path = priv->activating_connection ? nm_active_connection_get_path (priv->activating_connection) : "/";
		g_value_set_boxed (value, path);
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
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	for (iter = priv->active_connections; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *ac = iter->data;
		NMSettingsConnection *connection;

		if (nm_active_connection_get_state (ac) == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
			connection = NM_SETTINGS_CONNECTION (nm_active_connection_get_connection (ac));
			nm_settings_connection_update_timestamp (connection, (guint64) time (NULL), FALSE);
		}
	}

	return TRUE;
}

static void
dbus_connection_changed_cb (NMDBusManager *dbus_mgr,
                            DBusConnection *dbus_connection,
                            gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);

	if (dbus_connection) {
		/* Register property filter on new connection; there's no reason this
		 * should fail except out-of-memory or program error; if it does fail
		 * then there's no Manager property access control, which is bad.
		 */
		g_assert (dbus_connection_add_filter (dbus_connection, prop_filter, self, NULL));
	}
}

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *g_connection;
	guint i;
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
	priv->startup = TRUE;

	priv->dbus_mgr = nm_dbus_manager_get ();
	priv->dbus_connection_changed_id = g_signal_connect (priv->dbus_mgr,
	                                                     NM_DBUS_MANAGER_DBUS_CONNECTION_CHANGED,
	                                                     G_CALLBACK (dbus_connection_changed_cb),
	                                                     manager);

	priv->modem_manager = nm_modem_manager_get ();
	priv->modem_added_id = g_signal_connect (priv->modem_manager, "modem-added",
	                                         G_CALLBACK (modem_added), manager);
	priv->modem_removed_id = g_signal_connect (priv->modem_manager, "modem-removed",
	                                           G_CALLBACK (modem_removed), manager);

	priv->vpn_manager = nm_vpn_manager_get ();

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);

	/* avahi-autoipd stuff */
	priv->aipd_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                              NM_AUTOIP_DBUS_SERVICE,
	                                              "/",
	                                              NM_AUTOIP_DBUS_IFACE);
	if (priv->aipd_proxy) {
		dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
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

	/* sleep/wake handling */
	priv->sleep_monitor = nm_sleep_monitor_get ();
	g_signal_connect (priv->sleep_monitor, "sleeping",
	                  G_CALLBACK (sleeping_cb), manager);
	g_signal_connect (priv->sleep_monitor, "resuming",
	                  G_CALLBACK (resuming_cb), manager);

	/* Listen for authorization changes */
	nm_auth_changed_func_register (authority_changed_cb, manager);

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

	load_device_factories (manager);

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
		(object_class, PROP_STARTUP,
		 g_param_spec_boolean (NM_MANAGER_STARTUP,
		                       "Startup",
		                       "Is NetworkManager still starting up",
		                       TRUE,
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

	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY,
		 g_param_spec_uint (NM_MANAGER_CONNECTIVITY,
		                    "Connectivity",
		                    "Connectivity state",
		                    NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION,
		 g_param_spec_boxed (NM_MANAGER_PRIMARY_CONNECTION,
		                     "Primary connection",
		                     "Primary connection",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_ACTIVATING_CONNECTION,
		 g_param_spec_boxed (NM_MANAGER_ACTIVATING_CONNECTION,
		                     "Activating connection",
		                     "Activating connection",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE));

	/* Hostname is not exported over D-Bus */
	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_MANAGER_HOSTNAME,
		                      "Hostname",
		                      "Hostname",
		                      NULL,
		                      G_PARAM_READABLE));

	/* Sleeping is not exported over D-Bus */
	g_object_class_install_property
		(object_class, PROP_SLEEPING,
		 g_param_spec_boolean (NM_MANAGER_SLEEPING,
		                       "Sleeping",
		                       "Sleeping",
		                       FALSE,
		                       G_PARAM_READABLE));

	/* signals */
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, device_added),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, device_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMManagerClass, state_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[CHECK_PERMISSIONS] =
		g_signal_new ("check-permissions",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[USER_PERMISSIONS_CHANGED] =
		g_signal_new ("user-permissions-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[ACTIVE_CONNECTION_ADDED] =
		g_signal_new (NM_MANAGER_ACTIVE_CONNECTION_ADDED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[ACTIVE_CONNECTION_REMOVED] =
		g_signal_new (NM_MANAGER_ACTIVE_CONNECTION_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_OBJECT);

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (manager_class),
	                                        &dbus_glib_nm_manager_object_info);

	dbus_g_error_domain_register (NM_MANAGER_ERROR, NULL, NM_TYPE_MANAGER_ERROR);
	dbus_g_error_domain_register (NM_LOGGING_ERROR, "org.freedesktop.NetworkManager.Logging", NM_TYPE_LOGGING_ERROR);
}

