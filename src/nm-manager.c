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

#include "config.h"

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <glib/gi18n.h>

#include "nm-default.h"
#include "nm-manager.h"
#include "nm-bus-manager.h"
#include "nm-vpn-manager.h"
#include "nm-device.h"
#include "nm-device-generic.h"
#include "nm-dbus-glib-types.h"
#include "nm-platform.h"
#include "nm-rfkill-manager.h"
#include "nm-dhcp-manager.h"
#include "nm-settings.h"
#include "nm-settings-connection.h"
#include "nm-auth-utils.h"
#include "nm-auth-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-device-factory.h"
#include "nm-enum-types.h"
#include "nm-sleep-monitor.h"
#include "nm-connectivity.h"
#include "nm-policy.h"
#include "nm-connection-provider.h"
#include "nm-session-monitor.h"
#include "nm-activation-request.h"
#include "nm-core-internal.h"
#include "nm-config.h"
#include "nm-audit-manager.h"

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

static void impl_manager_set_logging (NMManager *manager,
                                      const char *level,
                                      const char *domains,
                                      DBusGMethodInvocation *context);

static void impl_manager_get_logging (NMManager *manager,
                                      char **level,
                                      char **domains);

static void impl_manager_check_connectivity (NMManager *manager,
                                             DBusGMethodInvocation *context);

#include "nm-manager-glue.h"

static void add_device (NMManager *self, NMDevice *device, gboolean try_assume);

static NMActiveConnection *_new_active_connection (NMManager *self,
                                                   NMConnection *connection,
                                                   const char *specific_object,
                                                   NMDevice *device,
                                                   NMAuthSubject *subject,
                                                   GError **error);

static void policy_activating_device_changed (GObject *object, GParamSpec *pspec, gpointer user_data);

static void rfkill_change (const char *desc, RfKillType rtype, gboolean enabled);

static gboolean find_master (NMManager *self,
                             NMConnection *connection,
                             NMDevice *device,
                             NMConnection **out_master_connection,
                             NMDevice **out_master_device,
                             NMActiveConnection **out_master_ac,
                             GError **error);

static void nm_manager_update_state (NMManager *manager);

#define SSD_POKE_INTERVAL 120
#define ORIGDEV_TAG "originating-device"

typedef struct {
	gboolean user_enabled;
	gboolean sw_enabled;
	gboolean hw_enabled;
	RfKillType rtype;
	const char *desc;
	const char *key;
	const char *prop;
	const char *hw_prop;
} RadioState;

typedef struct {
	char *state_file;

	GSList *active_connections;
	GSList *authorizing_connections;
	guint ac_cleanup_id;
	NMActiveConnection *primary_connection;
	NMActiveConnection *activating_connection;
	NMMetered metered;

	GSList *devices;
	NMState state;
	NMConfig *config;
	NMConnectivity *connectivity;

	NMPolicy *policy;

	NMBusManager  *dbus_mgr;
	gboolean       prop_filter_added;
	NMRfkillManager *rfkill_mgr;

	NMSettings *settings;
	char *hostname;

	RadioState radio_states[RFKILL_TYPE_MAX];
	gboolean sleeping;
	gboolean net_enabled;

	NMVpnManager *vpn_manager;

	NMSleepMonitor *sleep_monitor;

	GSList *auth_chains;

	/* Firmware dir monitor */
	GFileMonitor *fw_monitor;
	guint fw_changed_id;

	guint timestamp_update_id;

	gboolean startup;
} NMManagerPrivate;

#define NM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MANAGER, NMManagerPrivate))

G_DEFINE_TYPE (NMManager, nm_manager, NM_TYPE_EXPORTED_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGED,
	CHECK_PERMISSIONS,
	USER_PERMISSIONS_CHANGED,
	ACTIVE_CONNECTION_ADDED,
	ACTIVE_CONNECTION_REMOVED,
	CONFIGURE_QUIT,

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
	PROP_PRIMARY_CONNECTION_TYPE,
	PROP_ACTIVATING_CONNECTION,
	PROP_DEVICES,
	PROP_METERED,

	/* Not exported */
	PROP_HOSTNAME,
	PROP_SLEEPING,

	LAST_PROP
};


/************************************************************************/

static void active_connection_state_changed (NMActiveConnection *active,
                                             GParamSpec *pspec,
                                             NMManager *self);
static void active_connection_default_changed (NMActiveConnection *active,
                                               GParamSpec *pspec,
                                               NMManager *self);

/* Returns: whether to notify D-Bus of the removal or not */
static gboolean
active_connection_remove (NMManager *self, NMActiveConnection *active)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean notify = nm_exported_object_is_exported (NM_EXPORTED_OBJECT (active));
	GSList *found;

	/* FIXME: switch to a GList for faster removal */
	found = g_slist_find (priv->active_connections, active);
	if (found) {
		NMConnection *connection;

		priv->active_connections = g_slist_remove (priv->active_connections, active);
		g_signal_emit (self, signals[ACTIVE_CONNECTION_REMOVED], 0, active);
		g_signal_handlers_disconnect_by_func (active, active_connection_state_changed, self);
		g_signal_handlers_disconnect_by_func (active, active_connection_default_changed, self);

		if (   nm_active_connection_get_assumed (active)
		    && (connection = nm_active_connection_get_connection (active))
		    && nm_settings_connection_get_nm_generated_assumed (NM_SETTINGS_CONNECTION (connection)))
			g_object_ref (connection);
		else
			connection = NULL;

		g_object_unref (active);

		if (   connection
		    && nm_settings_has_connection (priv->settings, connection)) {
			nm_log_dbg (LOGD_DEVICE, "Assumed connection disconnected. Deleting generated connection '%s' (%s)",
			            nm_connection_get_id (connection), nm_connection_get_uuid (connection));
			nm_settings_connection_delete (NM_SETTINGS_CONNECTION (connection), NULL, NULL);
			g_object_unref (connection);
		}
	}

	return found && notify;
}

static gboolean
_active_connection_cleanup (gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	priv->ac_cleanup_id = 0;

	g_object_freeze_notify (G_OBJECT (self));
	iter = priv->active_connections;
	while (iter) {
		NMActiveConnection *ac = iter->data;

		iter = iter->next;
		if (nm_active_connection_get_state (ac) == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
			if (active_connection_remove (self, ac))
				g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
		}
	}
	g_object_thaw_notify (G_OBJECT (self));

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

	nm_manager_update_state (self);
}

static void
active_connection_default_changed (NMActiveConnection *active,
                                   GParamSpec *pspec,
                                   NMManager *self)
{
	nm_manager_update_state (self);
}

/**
 * active_connection_add():
 * @self: the #NMManager
 * @active: the #NMActiveConnection to manage
 *
 * Begins to track and manage @active.  Increases the refcount of @active.
 */
static void
active_connection_add (NMManager *self, NMActiveConnection *active)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (g_slist_find (priv->active_connections, active) == FALSE);

	priv->active_connections = g_slist_prepend (priv->active_connections,
	                                            g_object_ref (active));

	g_signal_connect (active,
	                  "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  G_CALLBACK (active_connection_state_changed),
	                  self);
	g_signal_connect (active,
	                  "notify::" NM_ACTIVE_CONNECTION_DEFAULT,
	                  G_CALLBACK (active_connection_default_changed),
	                  self);
	g_signal_connect (active,
	                  "notify::" NM_ACTIVE_CONNECTION_DEFAULT6,
	                  G_CALLBACK (active_connection_default_changed),
	                  self);

	g_signal_emit (self, signals[ACTIVE_CONNECTION_ADDED], 0, active);

	/* Only notify D-Bus if the active connection is actually exported */
	if (nm_exported_object_is_exported (NM_EXPORTED_OBJECT (active)))
		g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
}

const GSList *
nm_manager_get_active_connections (NMManager *manager)
{
	return NM_MANAGER_GET_PRIVATE (manager)->active_connections;
}

static NMActiveConnection *
find_ac_for_connection (NMManager *manager, NMConnection *connection)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;
	NMActiveConnection *ac;
	NMConnection *ac_connection;
	NMActiveConnectionState ac_state;
	const char *uuid;

	uuid = nm_connection_get_uuid (connection);
	for (iter = priv->active_connections; iter; iter = iter->next) {
		ac = iter->data;
		ac_connection = nm_active_connection_get_connection (ac);
		ac_state = nm_active_connection_get_state (ac);

		if (   !strcmp (nm_connection_get_uuid (ac_connection), uuid)
		    && (ac_state < NM_ACTIVE_CONNECTION_STATE_DEACTIVATED))
			return ac;
	}

	return NULL;
}

/* Filter out connections that are already active.
 * nm_settings_get_connections() returns sorted list. We need to preserve the
 * order so that we didn't change auto-activation order (recent timestamps
 * are first).
 * Caller is responsible for freeing the returned list with g_slist_free().
 */
GSList *
nm_manager_get_activatable_connections (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *all_connections = nm_settings_get_connections (priv->settings);
	GSList *connections = NULL, *iter;
	NMConnection *connection;

	for (iter = all_connections; iter; iter = iter->next) {
		connection = iter->data;

		if (!find_ac_for_connection (manager, connection))
			connections = g_slist_prepend (connections, connection);
	}

	g_slist_free (all_connections);
	return g_slist_reverse (connections);
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

		if (g_strcmp0 (path, nm_exported_object_get_path (NM_EXPORTED_OBJECT (candidate))) == 0)
			return candidate;
	}
	return NULL;
}

/************************************************************************/

static void
_config_changed_cb (NMConfig *config, NMConfigData *config_data, NMConfigChangeFlags changes, NMConfigData *old_data, NMManager *self)
{
	g_object_set (NM_MANAGER_GET_PRIVATE (self)->connectivity,
	              NM_CONNECTIVITY_URI, nm_config_data_get_connectivity_uri (config_data),
	              NM_CONNECTIVITY_INTERVAL, nm_config_data_get_connectivity_interval (config_data),
	              NM_CONNECTIVITY_RESPONSE, nm_config_data_get_connectivity_response (config_data),
	              NULL);
}

/************************************************************************/

static NMDevice *
nm_manager_get_device_by_path (NMManager *manager, const char *path)
{
	GSList *iter;

	g_return_val_if_fail (path != NULL, NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		if (!strcmp (nm_exported_object_get_path (NM_EXPORTED_OBJECT (iter->data)), path))
			return NM_DEVICE (iter->data);
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

static NMDevice *
find_device_by_hw_addr (NMManager *manager, const char *hwaddr)
{
	GSList *iter;
	const char *device_addr;

	g_return_val_if_fail (hwaddr != NULL, NULL);

	if (nm_utils_hwaddr_valid (hwaddr, -1)) {
		for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
			device_addr = nm_device_get_hw_address (NM_DEVICE (iter->data));
			if (device_addr && nm_utils_hwaddr_matches (hwaddr, -1, device_addr, -1))
				return NM_DEVICE (iter->data);
		}
	}
	return NULL;
}

static NMDevice *
find_device_by_ip_iface (NMManager *self, const gchar *iface)
{
	GSList *iter;

	g_return_val_if_fail (iface != NULL, NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (self)->devices; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (nm_device_get_ip_iface (NM_DEVICE (iter->data)), iface) == 0)
			return NM_DEVICE (iter->data);
	}
	return NULL;
}

static NMDevice *
find_device_by_iface (NMManager *self, const gchar *iface)
{
	GSList *iter;

	for (iter = NM_MANAGER_GET_PRIVATE (self)->devices; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (nm_device_get_iface (NM_DEVICE (iter->data)), iface) == 0)
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

static const char *
_nm_state_to_string (NMState state)
{
	switch (state) {
	case NM_STATE_ASLEEP:
		return "ASLEEP";
	case NM_STATE_DISCONNECTED:
		return "DISCONNECTED";
	case NM_STATE_DISCONNECTING:
		return "DISCONNECTING";
	case NM_STATE_CONNECTING:
		return "CONNECTING";
	case NM_STATE_CONNECTED_LOCAL:
		return "CONNECTED_LOCAL";
	case NM_STATE_CONNECTED_SITE:
		return "CONNECTED_SITE";
	case NM_STATE_CONNECTED_GLOBAL:
		return "CONNECTED_GLOBAL";
	case NM_STATE_UNKNOWN:
	default:
		return "UNKNOWN";
	}
}

static void
set_state (NMManager *manager, NMState state)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->state == state)
		return;

	priv->state = state;

	nm_log_info (LOGD_CORE, "NetworkManager state is now %s", _nm_state_to_string (state));

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
		g_object_notify (G_OBJECT (manager), NM_MANAGER_CONNECTIVITY);
	}

	g_object_unref (manager);
}

static NMState
find_best_device_state (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMState best_state = NM_STATE_DISCONNECTED;
	GSList *iter;

	for (iter = priv->active_connections; iter; iter = iter->next) {
		NMActiveConnection *ac = NM_ACTIVE_CONNECTION (iter->data);
		NMActiveConnectionState ac_state = nm_active_connection_get_state (ac);

		switch (ac_state) {
		case NM_ACTIVE_CONNECTION_STATE_ACTIVATED:
			if (   nm_active_connection_get_default (ac)
			    || nm_active_connection_get_default6 (ac)) {
				if (nm_connectivity_get_state (priv->connectivity) == NM_CONNECTIVITY_FULL)
					return NM_STATE_CONNECTED_GLOBAL;

				best_state = NM_STATE_CONNECTED_SITE;
			} else {
				if (best_state < NM_STATE_CONNECTING)
					best_state = NM_STATE_CONNECTED_LOCAL;
			}
			break;
		case NM_ACTIVE_CONNECTION_STATE_ACTIVATING:
			if (!nm_active_connection_get_assumed (ac)) {
				if (best_state != NM_STATE_CONNECTED_GLOBAL)
					best_state = NM_STATE_CONNECTING;
			}
			break;
		case NM_ACTIVE_CONNECTION_STATE_DEACTIVATING:
			if (!nm_active_connection_get_assumed (ac)) {
				if (best_state < NM_STATE_DISCONNECTING)
					best_state = NM_STATE_DISCONNECTING;
			}
			break;
		default:
			break;
		}
	}

	return best_state;
}

static void
nm_manager_update_metered (NMManager *manager)
{
	NMManagerPrivate *priv;
	NMDevice *device;
	NMMetered value = NM_METERED_UNKNOWN;

	g_return_if_fail (NM_IS_MANAGER (manager));
	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->primary_connection) {
		device =  nm_active_connection_get_device (priv->primary_connection);
		if (device)
			value = nm_device_get_metered (device);
	}

	if (value != priv->metered) {
		priv->metered = value;
		nm_log_dbg (LOGD_CORE, "New manager metered value: %d",
		            (int) priv->metered);
		g_object_notify (G_OBJECT (manager), NM_MANAGER_METERED);
	}
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
	else
		new_state = find_best_device_state (manager);

	nm_connectivity_set_online (priv->connectivity, new_state >= NM_STATE_CONNECTED_LOCAL);

	if (new_state == NM_STATE_CONNECTED_SITE) {
		nm_connectivity_check_async (priv->connectivity,
		                             checked_connectivity,
		                             g_object_ref (manager));
	}

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

	if (!nm_settings_get_startup_complete (priv->settings)) {
		nm_log_dbg (LOGD_CORE, "check_if_startup_complete returns FALSE because of NMSettings");
		return;
	}

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

	if (nm_config_get_configure_and_quit (nm_config_get ()))
		g_signal_emit (self, signals[CONFIGURE_QUIT], 0);
}

static void
device_has_pending_action_changed (NMDevice *device,
                                   GParamSpec *pspec,
                                   NMManager *self)
{
	check_if_startup_complete (self);
}

static void
settings_startup_complete_changed (NMSettings *settings,
                                   GParamSpec *pspec,
                                   NMManager *self)
{
	check_if_startup_complete (self);
}

static void
remove_device (NMManager *manager,
               NMDevice *device,
               gboolean quitting,
               gboolean allow_unmanage)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	nm_log_dbg (LOGD_DEVICE, "(%s): removing device (allow_unmanage %d, managed %d)",
	            nm_device_get_iface (device), allow_unmanage, nm_device_get_managed (device));

	if (allow_unmanage && nm_device_get_managed (device)) {
		NMActRequest *req = nm_device_get_act_request (device);
		gboolean unmanage = FALSE;

		/* Leave activated interfaces up when quitting so their configuration
		 * can be taken over when NM restarts.  This ensures connectivity while
		 * NM is stopped. Devices which do not support connection assumption
		 * cannot be left up.
		 */
		if (!quitting)  /* Forced removal; device already gone */
			unmanage = TRUE;
		else if (!nm_device_can_assume_active_connection (device))
			unmanage = TRUE;
		else if (!req)
			unmanage = TRUE;

		if (unmanage) {
			if (quitting)
				nm_device_set_unmanaged_quitting (device);
			else
				nm_device_set_unmanaged (device, NM_UNMANAGED_INTERNAL, TRUE, NM_DEVICE_STATE_REASON_REMOVED);
		} else if (quitting && nm_config_get_configure_and_quit (nm_config_get ())) {
			nm_device_spawn_iface_helper (device);
		}
	}

	g_signal_handlers_disconnect_matched (device, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, manager);

	nm_settings_device_removed (priv->settings, device, quitting);
	priv->devices = g_slist_remove (priv->devices, device);

	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, device);
	g_object_notify (G_OBJECT (manager), NM_MANAGER_DEVICES);
	nm_device_removed (device);

	nm_exported_object_unexport (NM_EXPORTED_OBJECT (device));
	g_object_unref (device);

	check_if_startup_complete (manager);
}

static void
device_removed_cb (NMDevice *device, gpointer user_data)
{
	remove_device (NM_MANAGER (user_data), device, FALSE, TRUE);
}

NMState
nm_manager_get_state (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_STATE_UNKNOWN);

	return NM_MANAGER_GET_PRIVATE (manager)->state;
}

/***************************/

static NMDevice *
find_parent_device_for_connection (NMManager *self, NMConnection *connection)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDeviceFactory *factory;
	const char *parent_name = NULL;
	NMConnection *parent_connection;
	NMDevice *parent, *first_compatible = NULL;
	GSList *iter;

	factory = nm_device_factory_manager_find_factory_for_connection (connection);
	if (!factory)
		return NULL;

	parent_name = nm_device_factory_get_connection_parent (factory, connection);
	if (!parent_name)
		return NULL;

	/* Try as an interface name */
	parent = find_device_by_ip_iface (self, parent_name);
	if (parent)
		return parent;

	/* Maybe a hardware address */
	parent = find_device_by_hw_addr (self, parent_name);
	if (parent)
		return parent;

	/* Maybe a connection UUID */
	parent_connection = (NMConnection *) nm_settings_get_connection_by_uuid (priv->settings, parent_name);
	if (!parent_connection)
		return NULL;

	/* Check if the parent connection is currently activated or is comaptible
	 * with some known device.
	 */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;

		if (nm_device_get_connection (candidate) == parent_connection)
			return candidate;

		if (   !first_compatible
		    && nm_device_check_connection_compatible (candidate, parent_connection))
			first_compatible = candidate;
	}

	return first_compatible;
}

/**
 * get_virtual_iface_name:
 * @self: the #NMManager
 * @connection: the #NMConnection representing a virtual interface
 * @out_parent: on success, the parent device if any
 * @error: an error if determining the virtual interface name failed
 *
 * Given @connection, returns the interface name that the connection
 * would represent if it is a virtual connection.  %NULL is returned and
 * @error is set if the connection is not virtual, or if the name could
 * not be determined.
 *
 * Returns: the expected interface name (caller takes ownership), or %NULL
 */
static char *
get_virtual_iface_name (NMManager *self,
                        NMConnection *connection,
                        NMDevice **out_parent,
                        GError **error)
{
	NMDeviceFactory *factory;
	char *iface = NULL;
	NMDevice *parent = NULL;

	if (out_parent)
		*out_parent = NULL;

	if (!nm_connection_is_virtual (connection)) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "NetworkManager plugin for '%s' unavailable",
		             nm_connection_get_connection_type (connection));
		return NULL;
	}

	factory = nm_device_factory_manager_find_factory_for_connection (connection);
	if (!factory) {
		nm_log_warn (LOGD_DEVICE, "(%s) NetworkManager plugin for '%s' unavailable",
		             nm_connection_get_id (connection),
		             nm_connection_get_connection_type (connection));
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "NetworkManager plugin for '%s' unavailable",
		             nm_connection_get_connection_type (connection));
		return NULL;
	}

	parent = find_parent_device_for_connection (self, connection);
	iface = nm_device_factory_get_virtual_iface_name (factory,
	                                                  connection,
	                                                  parent ? nm_device_get_ip_iface (parent) : NULL);
	if (!iface) {
		nm_log_warn (LOGD_DEVICE, "(%s) failed to determine virtual interface name",
		             nm_connection_get_id (connection));
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		                     "failed to determine virtual interface name");
		return NULL;
	}

	if (out_parent)
		*out_parent = parent;
	return iface;
}

/**
 * system_create_virtual_device:
 * @self: the #NMManager
 * @connection: the connection which might require a virtual device
 * @error: the error set when return value is NULL
 *
 * If @connection requires a virtual device and one does not yet exist for it,
 * creates that device.
 *
 * Returns: the #NMDevice if successfully created, %NULL if not
 */
static NMDevice *
system_create_virtual_device (NMManager *self, NMConnection *connection, GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDeviceFactory *factory;
	GSList *iter;
	char *iface = NULL;
	NMDevice *device = NULL, *parent = NULL;
	gboolean nm_owned = FALSE;

	g_return_val_if_fail (NM_IS_MANAGER (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	iface = get_virtual_iface_name (self, connection, &parent, error);
	if (!iface)
		return NULL;

	/* Make sure we didn't create a device for this connection already */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = iter->data;

		if (   g_strcmp0 (nm_device_get_iface (candidate), iface) == 0
		    || nm_device_check_connection_compatible (candidate, connection)) {
			nm_log_dbg (LOGD_DEVICE, "(%s) already created virtual interface name %s",
			            nm_connection_get_id (connection), iface);
			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_FAILED,
			             "interface name '%s' already created", iface);
			goto out;
		}
	}

	factory = nm_device_factory_manager_find_factory_for_connection (connection);
	if (!factory) {
		nm_log_err (LOGD_DEVICE, "(%s:%s) NetworkManager plugin for '%s' unavailable",
		            nm_connection_get_id (connection), iface,
		            nm_connection_get_connection_type (connection));
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "NetworkManager plugin for '%s' unavailable",
		             nm_connection_get_connection_type (connection));
		goto out;
	}

	nm_owned = !nm_platform_link_get_by_ifname (NM_PLATFORM_GET, iface);

	device = nm_device_factory_create_device (factory, iface, NULL, connection, NULL, error);
	if (device) {
		if (!nm_device_create_and_realize (device, connection, parent, error)) {
			g_clear_object (&device);
			goto out;
		}

		if (nm_owned)
			nm_device_set_nm_owned (device);

		/* If it was created by NM there's no connection to assume, but if it
		 * previously existed there might be one.
		 */
		add_device (self, device, !nm_owned);

		/* Add device takes a reference that NMManager still owns, so it's
		 * safe to unref here and still return @device.
		 */
		g_object_unref (device);
	}

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

		/* We only create a virtual interface if the connection can autoconnect */
		if (   nm_connection_is_virtual (connection)
		    && nm_settings_connection_can_autoconnect (NM_SETTINGS_CONNECTION (connection)))
			system_create_virtual_device (self, connection, NULL);
	}
	g_slist_free (connections);
}

static void
connection_added (NMSettings *settings,
                  NMSettingsConnection *settings_connection,
                  NMManager *manager)
{
	NMConnection *connection = NM_CONNECTION (settings_connection);

	if (nm_connection_is_virtual (connection)) {
		NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);

		g_assert (s_con);
		if (nm_setting_connection_get_autoconnect (s_con))
			system_create_virtual_device (manager, connection, NULL);
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
		gboolean unmanaged;

		unmanaged = nm_device_spec_match_list (device, unmanaged_specs);
		nm_device_set_unmanaged (device,
		                         NM_UNMANAGED_USER,
		                         unmanaged,
		                         unmanaged ? NM_DEVICE_STATE_REASON_NOW_UNMANAGED :
		                                     NM_DEVICE_STATE_REASON_NOW_MANAGED);
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

	nm_dhcp_manager_set_default_hostname (nm_dhcp_manager_get (), priv->hostname);

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
	if (check_changeable)
		enabled &= rstate->sw_enabled;
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
update_rstate_from_rfkill (NMRfkillManager *rfkill_mgr, RadioState *rstate)
{
	switch (nm_rfkill_manager_get_rfkill_state (rfkill_mgr, rstate->rtype)) {
	case RFKILL_UNBLOCKED:
		rstate->sw_enabled = TRUE;
		rstate->hw_enabled = TRUE;
		break;
	case RFKILL_SOFT_BLOCKED:
		rstate->sw_enabled = FALSE;
		rstate->hw_enabled = TRUE;
		break;
	case RFKILL_HARD_BLOCKED:
		rstate->sw_enabled = FALSE;
		rstate->hw_enabled = FALSE;
		break;
	default:
		g_warn_if_reached ();
		break;
	}
}

static void
manager_rfkill_update_one_type (NMManager *self,
                                RadioState *rstate,
                                RfKillType rtype)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean old_enabled, new_enabled, old_rfkilled, new_rfkilled, old_hwe;

	old_enabled = radio_enabled_for_rstate (rstate, TRUE);
	old_rfkilled = rstate->hw_enabled && rstate->sw_enabled;
	old_hwe = rstate->hw_enabled;

	/* recheck kernel rfkill state */
	update_rstate_from_rfkill (priv->rfkill_mgr, rstate);

	/* Print out all states affecting device enablement */
	if (rstate->desc) {
		nm_log_dbg (LOGD_RFKILL, "%s hw-enabled %d sw-enabled %d",
		            rstate->desc, rstate->hw_enabled, rstate->sw_enabled);
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
	NMAuthSubject *subject;

	g_assert (context);

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	permission = nm_auth_chain_get_data (chain, "requested-permission");
	g_assert (permission);
	callback = nm_auth_chain_get_data (chain, "callback");
	g_assert (callback);
	device = nm_auth_chain_get_data (chain, "device");
	g_assert (device);

	result = nm_auth_chain_get_result (chain, permission);
	subject = nm_auth_chain_get_subject (chain);

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
	          subject,
	          error,
	          nm_auth_chain_get_data (chain, "user-data"));

	g_clear_error (&error);
	nm_auth_chain_unref (chain);
}

static void
device_auth_request_cb (NMDevice *device,
                        DBusGMethodInvocation *context,
                        NMConnection *connection,
                        const char *permission,
                        gboolean allow_interaction,
                        NMDeviceAuthRequestFunc callback,
                        gpointer user_data,
                        NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthSubject *subject = NULL;
	char *error_desc = NULL;
	NMAuthChain *chain;

	/* Validate the caller */
	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Failed to get request UID.");
		goto done;
	}

	/* Ensure the subject has permissions for this connection */
	if (connection && !nm_auth_is_subject_in_acl (connection,
	                                              subject,
	                                              &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		g_free (error_desc);
		goto done;
	}

	/* Validate the request */
	chain = nm_auth_chain_new_subject (subject, context, device_auth_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		goto done;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "device", g_object_ref (device), g_object_unref);
	nm_auth_chain_set_data (chain, "requested-permission", g_strdup (permission), g_free);
	nm_auth_chain_set_data (chain, "callback", callback, NULL);
	nm_auth_chain_set_data (chain, "user-data", user_data, NULL);
	nm_auth_chain_add_call (chain, permission, allow_interaction);

done:
	if (error)
		callback (device, context, subject, error, user_data);

	g_clear_object (&subject);
	g_clear_error (&error);
}

static gboolean
match_connection_filter (NMConnection *connection, gpointer user_data)
{
	if (nm_settings_connection_get_nm_generated_assumed (NM_SETTINGS_CONNECTION (connection)))
		return FALSE;

	return nm_device_check_connection_compatible (NM_DEVICE (user_data), connection);
}

/**
 * get_existing_connection:
 * @manager: #NMManager instance
 * @device: #NMDevice instance
 * @out_generated: (allow-none): return TRUE, if the connection was generated.
 *
 * Returns: a #NMSettingsConnection to be assumed by the device, or %NULL if
 *   the device does not support assuming existing connections.
 */
static NMConnection *
get_existing_connection (NMManager *manager, NMDevice *device, gboolean *out_generated)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	gs_free_slist GSList *connections = nm_manager_get_activatable_connections (manager);
	NMConnection *connection = NULL, *matched;
	NMSettingsConnection *added = NULL;
	GError *error = NULL;
	NMDevice *master = NULL;
	int ifindex = nm_device_get_ifindex (device);

	if (out_generated)
		*out_generated = FALSE;

	nm_device_capture_initial_config (device);

	if (ifindex) {
		int master_ifindex = nm_platform_link_get_master (NM_PLATFORM_GET, ifindex);

		if (master_ifindex) {
			master = nm_manager_get_device_by_ifindex (manager, master_ifindex);
			if (!master) {
				nm_log_dbg (LOGD_DEVICE, "(%s): cannot generate connection for slave before its master (%s/%d)",
				            nm_device_get_iface (device), nm_platform_link_get_name (NM_PLATFORM_GET, master_ifindex), master_ifindex);
				return NULL;
			}
			if (!nm_device_get_act_request (master)) {
				nm_log_dbg (LOGD_DEVICE, "(%s): cannot generate connection for slave before master %s activates",
				            nm_device_get_iface (device), nm_device_get_iface (master));
				return NULL;
			}
		}
	}

	/* The core of the API is nm_device_generate_connection() function and
	 * update_connection() virtual method and the convenient connection_type
	 * class attribute. Subclasses supporting the new API must have
	 * update_connection() implemented, otherwise nm_device_generate_connection()
	 * returns NULL.
	 */
	connection = nm_device_generate_connection (device, master);
	if (!connection)
		return NULL;

	/* Now we need to compare the generated connection to each configured
	 * connection. The comparison function is the heart of the connection
	 * assumption implementation and it must compare the connections very
	 * carefully to sort out various corner cases. Also, the comparison is
	 * not entirely symmetric.
	 *
	 * When no configured connection matches the generated connection, we keep
	 * the generated connection instead.
	 */
	connections = g_slist_reverse (g_slist_sort (connections, nm_settings_sort_connections));
	matched = nm_utils_match_connection (connections,
	                                     connection,
	                                     nm_device_has_carrier (device),
	                                     match_connection_filter,
	                                     device);
	if (matched) {
		nm_log_info (LOGD_DEVICE, "(%s): found matching connection '%s'",
		             nm_device_get_iface (device),
		             nm_connection_get_id (matched));
		g_object_unref (connection);
		return matched;
	}

	nm_log_dbg (LOGD_DEVICE, "(%s): generated connection '%s'",
	            nm_device_get_iface (device),
	            nm_connection_get_id (connection));

	added = nm_settings_add_connection (priv->settings, connection, FALSE, &error);
	if (added) {
		nm_settings_connection_set_flags (NM_SETTINGS_CONNECTION (added),
		                                  NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED |
		                                  NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED_ASSUMED,
		                                  TRUE);
		if (out_generated)
			*out_generated = TRUE;
	} else {
		nm_log_warn (LOGD_SETTINGS, "(%s) Couldn't save generated connection '%s': %s",
		             nm_device_get_iface (device),
		             nm_connection_get_id (connection),
		             (error && error->message) ? error->message : "(unknown)");
		g_clear_error (&error);
	}
	g_object_unref (connection);

	return added ? NM_CONNECTION (added) : NULL;
}

static gboolean
assume_connection (NMManager *self, NMDevice *device, NMConnection *connection)
{
	NMActiveConnection *active, *master_ac;
	NMAuthSubject *subject;
	GError *error = NULL;

	nm_log_dbg (LOGD_DEVICE, "(%s): will attempt to assume connection",
	            nm_device_get_iface (device));

	/* Move device to DISCONNECTED to activate the connection */
	if (nm_device_get_state (device) == NM_DEVICE_STATE_UNAVAILABLE) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
	}
	g_return_val_if_fail (nm_device_get_state (device) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

	subject = nm_auth_subject_new_internal ();
	active = _new_active_connection (self, connection, NULL, device, subject, &error);
	g_object_unref (subject);

	if (!active) {
		nm_log_warn (LOGD_DEVICE, "assumed connection %s failed to activate: (%d) %s",
		             nm_connection_get_path (connection),
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_error_free (error);
		return FALSE;
	}

	/* If the device is a slave or VLAN, find the master ActiveConnection */
	master_ac = NULL;
	if (find_master (self, connection, device, NULL, NULL, &master_ac, NULL) && master_ac)
		nm_active_connection_set_master (active, master_ac);

	nm_active_connection_set_assumed (active, TRUE);
	nm_exported_object_export (NM_EXPORTED_OBJECT (active));
	active_connection_add (self, active);
	nm_device_queue_activation (device, NM_ACT_REQUEST (active));
	g_object_unref (active);

	return TRUE;
}

static gboolean
recheck_assume_connection (NMDevice *device, gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMConnection *connection;
	gboolean was_unmanaged = FALSE, success, generated;
	NMDeviceState state;

	if (manager_sleeping (self))
		return FALSE;
	if (nm_device_get_unmanaged_flag (device, NM_UNMANAGED_ALL & ~NM_UNMANAGED_DEFAULT))
		return FALSE;

	state = nm_device_get_state (device);
	if (state > NM_DEVICE_STATE_DISCONNECTED)
		return FALSE;

	connection = get_existing_connection (self, device, &generated);
	if (!connection) {
		nm_log_dbg (LOGD_DEVICE, "(%s): can't assume; no connection",
		            nm_device_get_iface (device));
		return FALSE;
	}

	if (state == NM_DEVICE_STATE_UNMANAGED) {
		was_unmanaged = TRUE;
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
	}

	success = assume_connection (self, device, connection);
	if (!success) {
		if (was_unmanaged) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_UNAVAILABLE,
			                         NM_DEVICE_STATE_REASON_CONFIG_FAILED);

			/* Return default-unmanaged devices to their original state */
			if (nm_device_get_unmanaged_flag (device, NM_UNMANAGED_DEFAULT)) {
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_UNMANAGED,
				                         NM_DEVICE_STATE_REASON_CONFIG_FAILED);
			}
		}

		if (generated) {
			nm_log_dbg (LOGD_DEVICE, "(%s): connection assumption failed. Deleting generated connection",
			            nm_device_get_iface (device));

			nm_settings_connection_delete (NM_SETTINGS_CONNECTION (connection), NULL, NULL);
		}
	}

	return success;
}

static void
device_ip_iface_changed (NMDevice *device,
                         GParamSpec *pspec,
                         NMManager *self)
{
	const char *ip_iface = nm_device_get_ip_iface (device);
	GSList *iter;

	/* Remove NMDevice objects that are actually child devices of others,
	 * when the other device finally knows its IP interface name.  For example,
	 * remove the PPP interface that's a child of a WWAN device, since it's
	 * not really a standalone NMDevice.
	 */
	for (iter = NM_MANAGER_GET_PRIVATE (self)->devices; iter; iter = iter->next) {
		NMDevice *candidate = NM_DEVICE (iter->data);

		if (   candidate != device
		    && g_strcmp0 (nm_device_get_iface (candidate), ip_iface) == 0) {
			remove_device (self, candidate, FALSE, FALSE);
			break;
		}
	}
}

static gboolean
notify_component_added (NMManager *self, GObject *component)
{
	GSList *iter;

	for (iter = NM_MANAGER_GET_PRIVATE (self)->devices; iter; iter = iter->next) {
		if (nm_device_notify_component_added (NM_DEVICE (iter->data), component))
			return TRUE;
	}
	return FALSE;
}

/**
 * add_device:
 * @self: the #NMManager
 * @device: the #NMDevice to add
 * @try_assume: %TRUE if existing connection (if any) should be assumed
 *
 * If successful, this function will increase the references count of @device.
 * Callers should decrease the reference count.
 */
static void
add_device (NMManager *self, NMDevice *device, gboolean try_assume)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const char *iface, *driver, *type_desc;
	const GSList *unmanaged_specs;
	gboolean user_unmanaged, sleeping;
	gboolean enabled = FALSE;
	RfKillType rtype;
	GSList *iter, *remove = NULL;
	gboolean connection_assumed = FALSE;
	int ifindex;
	const char *dbus_path;

	/* No duplicates */
	ifindex = nm_device_get_ifindex (device);
	if (ifindex > 0 && nm_manager_get_device_by_ifindex (self, ifindex))
		return;
	if (find_device_by_iface (self, nm_device_get_iface (device)))
		return;

	/* Remove existing devices owned by the new device; eg remove ethernet
	 * ports that are owned by a WWAN modem, since udev may announce them
	 * before the modem is fully discovered.
	 *
	 * FIXME: use parent/child device relationships instead of removing
	 * the child NMDevice entirely
	 */
	for (iter = priv->devices; iter; iter = iter->next) {
		iface = nm_device_get_ip_iface (iter->data);
		if (nm_device_owns_iface (device, iface))
			remove = g_slist_prepend (remove, iter->data);
	}
	for (iter = remove; iter; iter = iter->next)
		remove_device (self, NM_DEVICE (iter->data), FALSE, FALSE);
	g_slist_free (remove);

	priv->devices = g_slist_append (priv->devices, g_object_ref (device));

	g_signal_connect (device, "state-changed",
	                  G_CALLBACK (manager_device_state_changed),
	                  self);

	g_signal_connect (device, NM_DEVICE_AUTH_REQUEST,
	                  G_CALLBACK (device_auth_request_cb),
	                  self);

	g_signal_connect (device, NM_DEVICE_REMOVED,
	                  G_CALLBACK (device_removed_cb),
	                  self);

	g_signal_connect (device, "notify::" NM_DEVICE_IP_IFACE,
	                  G_CALLBACK (device_ip_iface_changed),
	                  self);

	if (priv->startup) {
		g_signal_connect (device, "notify::" NM_DEVICE_HAS_PENDING_ACTION,
		                  G_CALLBACK (device_has_pending_action_changed),
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

	iface = nm_device_get_iface (device);
	g_assert (iface);

	type_desc = nm_device_get_type_desc (device);
	g_assert (type_desc);
	driver = nm_device_get_driver (device);
	if (!driver)
		driver = "unknown";
	nm_log_info (LOGD_HW, "(%s): new %s device (carrier: %s, driver: '%s', ifindex: %d)",
	             iface, type_desc,
	             nm_device_has_capability (device, NM_DEVICE_CAP_CARRIER_DETECT)
	                ? (nm_device_has_carrier (device) ? "ON" : "OFF")
	                : "UNKNOWN",
	             driver, nm_device_get_ifindex (device));

	unmanaged_specs = nm_settings_get_unmanaged_specs (priv->settings);
	user_unmanaged = nm_device_spec_match_list (device, unmanaged_specs);
	nm_device_set_initial_unmanaged_flag (device, NM_UNMANAGED_USER, user_unmanaged);

	sleeping = manager_sleeping (self);
	nm_device_set_initial_unmanaged_flag (device, NM_UNMANAGED_INTERNAL, sleeping);

	dbus_path = nm_exported_object_export (NM_EXPORTED_OBJECT (device));
	nm_log_dbg (LOGD_DEVICE, "(%s): exported as %s", nm_device_get_iface (device), dbus_path);

	nm_device_finish_init (device);

	if (try_assume) {
		connection_assumed = recheck_assume_connection (device, self);
		g_signal_connect (device, NM_DEVICE_RECHECK_ASSUME,
		                  G_CALLBACK (recheck_assume_connection), self);
	}

	if (!connection_assumed && nm_device_get_managed (device)) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_UNAVAILABLE,
		                         NM_DEVICE_STATE_REASON_NOW_MANAGED);
	}

	nm_settings_device_added (priv->settings, device);
	g_signal_emit (self, signals[DEVICE_ADDED], 0, device);
	g_object_notify (G_OBJECT (self), NM_MANAGER_DEVICES);

	notify_component_added (self, G_OBJECT (device));

	/* New devices might be master interfaces for virtual interfaces; so we may
	 * need to create new virtual interfaces now.
	 */
	system_create_virtual_devices (self);
}

/*******************************************************************/

static void
factory_device_added_cb (NMDeviceFactory *factory,
                         NMDevice *device,
                         gpointer user_data)
{
	GError *error = NULL;

	if (nm_device_realize (device, NULL, &error))
		add_device (NM_MANAGER (user_data), device, TRUE);
	else {
		nm_log_warn (LOGD_DEVICE, "(%s): failed to realize device: %s",
		             nm_device_get_iface (device), error->message);
		g_error_free (error);
	}
}

static gboolean
factory_component_added_cb (NMDeviceFactory *factory,
                            GObject *component,
                            gpointer user_data)
{
	return notify_component_added (NM_MANAGER (user_data), component);
}

static void
_register_device_factory (NMDeviceFactory *factory, gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);

	g_signal_connect (factory,
	                  NM_DEVICE_FACTORY_DEVICE_ADDED,
	                  G_CALLBACK (factory_device_added_cb),
	                  self);
	g_signal_connect (factory,
	                  NM_DEVICE_FACTORY_COMPONENT_ADDED,
	                  G_CALLBACK (factory_component_added_cb),
	                  self);
}

/*******************************************************************/

static void
platform_link_added (NMManager *self,
                     int ifindex,
                     NMPlatformLink *plink)
{
	NMDeviceFactory *factory;
	NMDevice *device = NULL;
	GError *error = NULL;
	gboolean nm_plugin_missing = FALSE;

	g_return_if_fail (ifindex > 0);

	if (nm_manager_get_device_by_ifindex (self, ifindex))
		return;

	/* Try registered device factories */
	factory = nm_device_factory_manager_find_factory_for_link_type (plink->type);
	if (factory) {
		gboolean ignore = FALSE;

		device = nm_device_factory_create_device (factory, plink->name, plink, NULL, &ignore, &error);
		if (!device) {
			if (!ignore) {
				nm_log_warn (LOGD_HW, "%s: factory failed to create device: %s",
				             plink->name, error->message);
				g_clear_error (&error);
			}
			return;
		} else if (!nm_device_realize (device, plink, &error)) {
			nm_log_warn (LOGD_HW, "%s: factory failed to create device: %s",
			             plink->name, error->message);
			g_clear_error (&error);
			return;
		}
	}

	if (device == NULL) {
		switch (plink->type) {
		case NM_LINK_TYPE_WWAN_ETHERNET:
		case NM_LINK_TYPE_BNEP:
		case NM_LINK_TYPE_OLPC_MESH:
		case NM_LINK_TYPE_TEAM:
		case NM_LINK_TYPE_WIFI:
			nm_log_info (LOGD_HW, "(%s): '%s' plugin not available; creating generic device",
			             plink->name, nm_link_type_to_string (plink->type));
			nm_plugin_missing = TRUE;
			/* fall through */
		default:
			device = nm_device_generic_new (plink);
			break;
		}
	}

	if (device) {
		if (nm_plugin_missing)
			nm_device_set_nm_plugin_missing (device, TRUE);
		add_device (self, device, plink->type != NM_LINK_TYPE_LOOPBACK);
		g_object_unref (device);
	}
}

typedef struct {
	NMManager *self;
	int ifindex;
} PlatformLinkCbData;

static gboolean
_platform_link_cb_idle (PlatformLinkCbData *data)
{
	NMManager *self = data->self;

	if (self) {
		const NMPlatformLink *l;

		l = nm_platform_link_get (NM_PLATFORM_GET, data->ifindex);
		if (l) {
			NMPlatformLink pllink;

			pllink = *l; /* make a copy of the link instance */
			platform_link_added (self, data->ifindex, &pllink);
		} else {
			NMDevice *device;

			device = nm_manager_get_device_by_ifindex (self, data->ifindex);
			if (device)
				remove_device (self, device, FALSE, TRUE);
		}
		g_object_remove_weak_pointer (G_OBJECT (self), (gpointer *) &data->self);
	}
	g_slice_free (PlatformLinkCbData, data);
	return G_SOURCE_REMOVE;
}

static void
platform_link_cb (NMPlatform *platform,
                  NMPObjectType obj_type,
                  int ifindex,
                  NMPlatformLink *plink,
                  NMPlatformSignalChangeType change_type,
                  NMPlatformReason reason,
                  gpointer user_data)
{
	PlatformLinkCbData *data;

	switch (change_type) {
	case NM_PLATFORM_SIGNAL_ADDED:
	case NM_PLATFORM_SIGNAL_REMOVED:
		data = g_slice_new (PlatformLinkCbData);
		data->self = NM_MANAGER (user_data);
		data->ifindex = ifindex;
		g_object_add_weak_pointer (G_OBJECT (data->self), (gpointer *) &data->self);
		g_idle_add ((GSourceFunc) _platform_link_cb_idle, data);
		break;
	default:
		break;
	}
}

static void
platform_query_devices (NMManager *self)
{
	GArray *links_array;
	NMPlatformLink *links;
	int i;

	links_array = nm_platform_link_get_all (NM_PLATFORM_GET);
	links = (NMPlatformLink *) links_array->data;
	for (i = 0; i < links_array->len; i++)
		platform_link_added (self, links[i].ifindex, &links[i]);

	g_array_unref (links_array);
}

static void
rfkill_manager_rfkill_changed_cb (NMRfkillManager *rfkill_mgr,
                                  RfKillType rtype,
                                  RfKillState udev_state,
                                  gpointer user_data)
{
	nm_manager_rfkill_update (NM_MANAGER (user_data), rtype);
}

const GSList *
nm_manager_get_devices (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->devices;
}

static NMDevice *
nm_manager_get_connection_device (NMManager *self,
                                  NMConnection *connection)
{
	NMActiveConnection *ac = find_ac_for_connection (self, connection);
	if (ac == NULL)
		return NULL;

	return nm_active_connection_get_device (ac);
}

static NMDevice *
nm_manager_get_best_device_for_connection (NMManager *self,
                                           NMConnection *connection)
{
	const GSList *devices, *iter;
	NMDevice *act_device = nm_manager_get_connection_device (self, connection);

	if (act_device)
		return act_device;

	/* Pick the first device that's compatible with the connection. */
	devices = nm_manager_get_devices (self);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_check_connection_available (device, connection, NM_DEVICE_CHECK_CON_AVAILABLE_NONE, NULL))
			return device;
	}

	/* No luck. :( */
	return NULL;
}

static gboolean
impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	*devices = g_ptr_array_sized_new (g_slist_length (priv->devices));

	for (iter = priv->devices; iter; iter = iter->next)
		g_ptr_array_add (*devices, g_strdup (nm_exported_object_get_path (NM_EXPORTED_OBJECT (iter->data))));
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
		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (device));
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
 * find_master:
 * @self: #NMManager object
 * @connection: the #NMConnection to find the master connection and device for
 * @device: the #NMDevice, if any, which will activate @connection
 * @out_master_connection: on success, the master connection of @connection if
 *   that master connection was found
 * @out_master_device: on success, the master device of @connection if that
 *   master device was found
 * @out_master_ac: on success, the master ActiveConnection of @connection if
 *   there already is one
 * @error: the error, if an error occurred
 *
 * Given an #NMConnection, attempts to find its master. If @connection has
 * no master, this will return %TRUE and @out_master_connection and
 * @out_master_device will be untouched.
 *
 * If @connection does have a master, then the outputs depend on what is in its
 * #NMSettingConnection:master property:
 *
 * If "master" is the ifname of an existing #NMDevice, and that device has a
 * compatible master connection activated or activating on it, then
 * @out_master_device, @out_master_connection, and @out_master_ac will all be
 * set. If the device exists and is idle, only @out_master_device will be set.
 * If the device exists and has an incompatible connection on it, an error
 * will be returned.
 *
 * If "master" is the ifname of a non-existent device, then @out_master_device
 * will be %NULL, and @out_master_connection will be a connection whose
 * activation would cause the creation of that device. @out_master_ac MAY be
 * set in this case as well (if the connection has started activating, but has
 * not yet created its device).
 *
 * If "master" is the UUID of a compatible master connection, then
 * @out_master_connection will be the identified connection, and @out_master_device
 * and/or @out_master_ac will be set if the connection is currently activating.
 * (@out_master_device will not be set if the device exists but does not have
 * @out_master_connection active/activating on it.)
 *
 * Returns: %TRUE if the master device and/or connection could be found or if
 *  the connection did not require a master, %FALSE otherwise
 **/
static gboolean
find_master (NMManager *self,
             NMConnection *connection,
             NMDevice *device,
             NMConnection **out_master_connection,
             NMDevice **out_master_device,
             NMActiveConnection **out_master_ac,
             GError **error)
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
		if (master_device == device) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			                     "Device cannot be its own master");
			return FALSE;
		}

		master_connection = nm_device_get_connection (master_device);
		if (master_connection && !is_compatible_with_slave (master_connection, connection)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			             "The active connection on %s is not a valid master for '%s'",
			             nm_device_get_iface (master_device),
			             nm_connection_get_id (connection));
			return FALSE;
		}
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
			connections = nm_manager_get_activatable_connections (self);
			for (iter = connections; iter && !master_connection; iter = g_slist_next (iter)) {
				NMConnection *candidate = iter->data;
				char *vname;

				vname = get_virtual_iface_name (self, candidate, NULL, NULL);
				if (g_strcmp0 (master, vname) == 0 && is_compatible_with_slave (candidate, connection))
					master_connection = candidate;
				g_free (vname);
			}
			g_slist_free (connections);
		}
	}

	if (out_master_connection)
		*out_master_connection = master_connection;
	if (out_master_device)
		*out_master_device = master_device;
	if (out_master_ac && master_connection)
		*out_master_ac = find_ac_for_connection (self, master_connection);

	if (master_device || master_connection)
		return TRUE;
	else {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		                     "Master connection not found or invalid");
		return FALSE;
	}
}

/**
 * ensure_master_active_connection:
 * @self: the #NMManager
 * @subject: the #NMAuthSubject representing the requestor of this activation
 * @connection: the connection that should depend on @master_connection
 * @device: the #NMDevice, if any, which will activate @connection
 * @master_connection: the master connection, or %NULL
 * @master_device: the master device, or %NULL
 * @error: the error, if an error occurred
 *
 * Determines whether a given #NMConnection depends on another connection to
 * be activated, and if so, finds that master connection or creates it.
 *
 * If @master_device and @master_connection are both set then @master_connection
 * MUST already be activated or activating on @master_device, and the function will
 * return the existing #NMActiveConnection.
 *
 * If only @master_device is set, and it has an #NMActiveConnection, then the
 * function will return it if it is a compatible master, or an error if not. If it
 * doesn't have an AC, then the function will create one if a compatible master
 * connection exists, or return an error if not.
 *
 * If only @master_connection is set, then this will try to find or create a compatible
 * #NMDevice, and either activate @master_connection on that device or return an error.
 *
 * Returns: the master #NMActiveConnection that the caller should depend on, or
 * %NULL if an error occurred
 */
static NMActiveConnection *
ensure_master_active_connection (NMManager *self,
                                 NMAuthSubject *subject,
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
		NMConnection *device_connection = nm_device_get_connection (master_device);

		/* If we're passed a connection and a device, we require that connection
		 * be already activated on the device, eg returned from find_master().
		 */
		g_assert (!master_connection || master_connection == device_connection);
		if (device_connection && !is_compatible_with_slave (device_connection, connection)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			             "The active connection on %s is not a valid master for '%s'",
			             nm_device_get_iface (master_device),
			             nm_connection_get_id (connection));
			return NULL;
		}

		master_state = nm_device_get_state (master_device);
		if (   (master_state == NM_DEVICE_STATE_ACTIVATED)
		    || nm_device_is_activating (master_device)) {
			/* Device already using master_connection */
			g_assert (device_connection);
			return NM_ACTIVE_CONNECTION (nm_device_get_act_request (master_device));
		}

		/* If the device is disconnected, find a compatible connection and
		 * activate it on the device.
		 */
		if (master_state == NM_DEVICE_STATE_DISCONNECTED) {
			GSList *connections;

			g_assert (master_connection == NULL);

			/* Find a compatible connection and activate this device using it */
			connections = nm_manager_get_activatable_connections (self);
			for (iter = connections; iter; iter = g_slist_next (iter)) {
				NMConnection *candidate = NM_CONNECTION (iter->data);

				/* Ensure eg bond/team slave and the candidate master is a
				 * bond/team master
				 */
				if (!is_compatible_with_slave (candidate, connection))
					continue;

				if (nm_device_check_connection_available (master_device, candidate, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL)) {
					master_ac = nm_manager_activate_connection (self,
					                                            candidate,
					                                            NULL,
					                                            master_device,
					                                            subject,
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
		             NM_MANAGER_ERROR_DEPENDENCY_FAILED,
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

			if (!nm_device_check_connection_available (candidate, master_connection, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL))
				continue;

			found_device = TRUE;
			master_state = nm_device_get_state (candidate);
			if (master_state != NM_DEVICE_STATE_DISCONNECTED)
				continue;

			master_ac = nm_manager_activate_connection (self,
			                                            master_connection,
			                                            NULL,
			                                            candidate,
			                                            subject,
			                                            error);
			if (!master_ac)
				g_prefix_error (error, "%s", "Master device activation failed: ");
			return master_ac;
		}

		/* Device described by master_connection may be a virtual one that's
		 * not created yet.
		 */
		if (!found_device && nm_connection_is_virtual (master_connection)) {
			master_ac = nm_manager_activate_connection (self,
			                                            master_connection,
			                                            NULL,
			                                            NULL,
			                                            subject,
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

/**
 * find_slaves:
 * @manager: #NMManager object
 * @connection: the master #NMConnection to find slave connections for
 * @device: the master #NMDevice for the @connection
 *
 * Given an #NMConnection, attempts to find its slaves. If @connection is not
 * master, or has not any slaves, this will return %NULL.
 *
 * Returns: list of slave connections for given master @connection, or %NULL
 **/
static GSList *
find_slaves (NMManager *manager,
             NMConnection *connection,
             NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *all_connections, *iter;
	GSList *slaves = NULL;
	NMSettingConnection *s_con;
	const char *master;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	master = nm_setting_connection_get_master (s_con);

	if (master != NULL)
		return NULL;  /* connection is not master */

	/* Search through all connections, not only inactive ones, because
	 * even if a slave was already active, it might be deactivated during
	 * master reactivation.
	 */
	all_connections = nm_settings_get_connections (priv->settings);
	for (iter = all_connections; iter; iter = iter->next) {
		NMConnection *master_connection = NULL;
		NMDevice *master_device = NULL;
		NMConnection *candidate = iter->data;

		find_master (manager, candidate, NULL, &master_connection, &master_device, NULL, NULL);
		if (   (master_connection && master_connection == connection)
		    || (master_device && master_device == device)) {
			slaves = g_slist_prepend (slaves, candidate);
		}
	}
	g_slist_free (all_connections);

	return g_slist_reverse (slaves);
}

static gboolean
should_connect_slaves (NMConnection *connection, NMDevice *device)
{
	NMSettingConnection *s_con;
	NMSettingConnectionAutoconnectSlaves autoconnect_slaves;
	gs_free char *value = NULL;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	/* Check autoconnect-slaves property */
	autoconnect_slaves = nm_setting_connection_get_autoconnect_slaves (s_con);
	if (autoconnect_slaves != NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT)
		goto out;

	/* Check configuration default for autoconnect-slaves property */
	value = nm_config_data_get_connection_default (NM_CONFIG_GET_DATA,
	                                               "connection.autoconnect-slaves", device);
	if (value)
		autoconnect_slaves = _nm_utils_ascii_str_to_int64 (value, 10, 0, 1, -1);

out:
	if (autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO)
		return FALSE;
	if (autoconnect_slaves == NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES)
		return TRUE;
	return FALSE;
}

static gboolean
autoconnect_slaves (NMManager *manager,
                    NMConnection *master_connection,
                    NMDevice *master_device,
                    NMAuthSubject *subject)
{
	GError *local_err = NULL;
	gboolean ret = FALSE;

	if (should_connect_slaves (master_connection, master_device)) {
		GSList *slaves, *iter;

		iter = slaves = find_slaves (manager, master_connection, master_device);
		ret = slaves != NULL;

		while (iter) {
			NMConnection *slave_connection = iter->data;

			iter = iter->next;
			nm_log_dbg (LOGD_CORE, "will activate slave connection '%s' (%s) as a dependency for master '%s' (%s)",
			            nm_connection_get_id (slave_connection),
			            nm_connection_get_uuid (slave_connection),
			            nm_connection_get_id (master_connection),
			            nm_connection_get_uuid (master_connection));

			/* Schedule slave activation */
			nm_manager_activate_connection (manager,
			                                slave_connection,
			                                NULL,
			                                nm_manager_get_best_device_for_connection (manager, slave_connection),
			                                subject,
			                                &local_err);
			if (local_err) {
				nm_log_warn (LOGD_CORE, "Slave connection activation failed: %s", local_err->message);
				g_error_free (local_err);
			}
		}
		g_slist_free (slaves);
	}
	return ret;
}

static gboolean
_internal_activate_vpn (NMManager *self, NMActiveConnection *active, GError **error)
{
	gboolean success;

	g_assert (NM_IS_VPN_CONNECTION (active));

	success = nm_vpn_manager_activate_connection (NM_MANAGER_GET_PRIVATE (self)->vpn_manager,
	                                              NM_VPN_CONNECTION (active),
	                                              error);
	if (success) {
		nm_exported_object_export (NM_EXPORTED_OBJECT (active));
		g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
	}
	return success;
}

static gboolean
_internal_activate_device (NMManager *self, NMActiveConnection *active, GError **error)
{
	NMDevice *device, *existing, *master_device = NULL;
	NMConnection *connection;
	NMConnection *master_connection = NULL;
	NMActiveConnection *master_ac = NULL;
	GError *local_err = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (self), FALSE);
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (active), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	g_assert (NM_IS_VPN_CONNECTION (active) == FALSE);

	connection = nm_active_connection_get_connection (active);
	g_assert (connection);

	device = nm_active_connection_get_device (active);
	if (!device) {
		if (!nm_connection_is_virtual (connection)) {
			NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);

			g_assert (s_con);
			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "Unsupported virtual interface type '%s'",
			             nm_setting_connection_get_connection_type (s_con));
			return FALSE;
		}

		device = system_create_virtual_device (self, connection, &local_err);
		if (!device) {
			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "Failed to create virtual interface: %s",
			             local_err ? local_err->message : "(unknown)");
			g_clear_error (&local_err);
			return FALSE;
		}

		if (!nm_active_connection_set_device (active, device)) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR,
			                     NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                     "The device could not be activated with this connection");
			return FALSE;
		}

		/* A newly created device, if allowed to be managed by NM, will be
		 * in the UNAVAILABLE state here.  To ensure it can be activated
		 * immediately, we transition it to DISCONNECTED.
		 */
		if (   nm_device_is_available (device, NM_DEVICE_CHECK_DEV_AVAILABLE_NONE)
			&& (nm_device_get_state (device) == NM_DEVICE_STATE_UNAVAILABLE)) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_NONE);
		}
	} else {
		NMConnection *existing_connection = NULL;
		NMAuthSubject *subject;
		char *error_desc = NULL;

		/* If the device is active and its connection is not visible to the
		 * user that's requesting this new activation, fail, since other users
		 * should not be allowed to implicitly deactivate private connections
		 * by activating a connection of their own.
		 */
		existing_connection = nm_device_get_connection (device);
		subject = nm_active_connection_get_subject (active);
		if (existing_connection &&
		    !nm_auth_is_subject_in_acl (existing_connection,
			                            subject,
			                            &error_desc)) {
			g_set_error (error,
					     NM_MANAGER_ERROR,
					     NM_MANAGER_ERROR_PERMISSION_DENIED,
					     "Private connection already active on the device: %s",
					     error_desc);
			g_free (error_desc);
			return FALSE;
		}
	}

	/* Final connection must be available on device */
	if (!nm_device_check_connection_available (device, connection, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		             "Connection '%s' is not available on the device %s at this time.",
		             nm_connection_get_id (connection), nm_device_get_iface (device));
		return FALSE;
	}

	/* If this is an autoconnect request, but the device isn't allowing autoconnect
	 * right now, we reject it.
	 */
	if (!nm_active_connection_get_user_requested (active) &&
	    !nm_device_autoconnect_allowed (device)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_AVAILABLE,
		             "%s does not allow automatic connections at this time",
		             nm_device_get_iface (device));
		return FALSE;
	}

	/* Try to find the master connection/device if the connection has a dependency */
	if (!find_master (self, connection, device,
	                  &master_connection, &master_device, &master_ac,
	                  error))
		return FALSE;

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

		/* Ensure eg bond slave and the candidate master is a bond master */
		if (master_connection && !is_compatible_with_slave (master_connection, connection)) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			                     "The master connection was not compatible");
			return FALSE;
		}

		if (!master_ac) {
			master_ac = ensure_master_active_connection (self,
			                                             nm_active_connection_get_subject (active),
			                                             connection,
			                                             device,
			                                             master_connection,
			                                             master_device,
			                                             error);
			if (!master_ac) {
				if (error)
					g_assert (*error);
				return FALSE;
			}
		}

		nm_active_connection_set_master (active, master_ac);
		nm_log_dbg (LOGD_CORE, "Activation of '%s' depends on active connection %p",
		            nm_connection_get_id (connection),
		            master_ac);
	}

	/* Check slaves for master connection and possibly activate them */
	autoconnect_slaves (self, connection, device, nm_active_connection_get_subject (active));

	/* Disconnect the connection if connected or queued on another device */
	existing = nm_manager_get_connection_device (self, connection);
	if (existing)
		nm_device_steal_connection (existing, connection);

	/* Export the new ActiveConnection to clients and start it on the device */
	nm_exported_object_export (NM_EXPORTED_OBJECT (active));
	g_object_notify (G_OBJECT (self), NM_MANAGER_ACTIVE_CONNECTIONS);
	nm_device_queue_activation (device, NM_ACT_REQUEST (active));
	return TRUE;
}

static gboolean
_internal_activate_generic (NMManager *self, NMActiveConnection *active, GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean success = FALSE;

	/* Ensure activation request is still valid, eg that its device hasn't gone
	 * away or that some other dependency has not failed.
	 */
	if (nm_active_connection_get_state (active) >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_DEPENDENCY_FAILED,
		                     "Activation failed because dependencies failed.");
		return FALSE;
	}

	if (NM_IS_VPN_CONNECTION (active))
		success = _internal_activate_vpn (self, active, error);
	else
		success = _internal_activate_device (self, active, error);

	if (success) {
		/* Force an update of the Manager's activating-connection property.
		 * The device changes state before the AC gets exported, which causes
		 * the manager's 'activating-connection' property to be NULL since the
		 * AC only gets a D-Bus path when it's exported.  So now that the AC
		 * is exported, make sure the manager's activating-connection property
		 * is up-to-date.
		 */
		active_connection_add (self, active);
		policy_activating_device_changed (G_OBJECT (priv->policy), NULL, self);
	}

	return success;
}

static NMActiveConnection *
_new_vpn_active_connection (NMManager *self, 
                            NMConnection *connection,
                            const char *specific_object,
                            NMAuthSubject *subject,
                            GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *parent = NULL;
	NMDevice *device = NULL;

	if (specific_object) {
		/* Find the specific connection the client requested we use */
		parent = active_connection_get_by_path (self, specific_object);
		if (!parent) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
			                     "Base connection for VPN connection not active.");
			return NULL;
		}
	} else
		parent = priv->primary_connection;

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

	return (NMActiveConnection *) nm_vpn_connection_new (connection,
	                                                     device,
	                                                     nm_exported_object_get_path (NM_EXPORTED_OBJECT (parent)),
	                                                     subject);
}

static NMActiveConnection *
_new_active_connection (NMManager *self,
                        NMConnection *connection,
                        const char *specific_object,
                        NMDevice *device,
                        NMAuthSubject *subject,
                        GError **error)
{
	NMActiveConnection *existing_ac;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);

	/* Can't create new AC for already-active connection */
	existing_ac = find_ac_for_connection (self, connection);
	if (NM_IS_VPN_CONNECTION (existing_ac)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_ALREADY_ACTIVE,
		             "Connection '%s' is already active",
		             nm_connection_get_id (connection));
		return NULL;
	}

	/* Normalize the specific object */
	if (specific_object && g_strcmp0 (specific_object, "/") == 0)
		specific_object = NULL;

	if (nm_connection_is_type (connection, NM_SETTING_VPN_SETTING_NAME)) {
		return _new_vpn_active_connection (self,
		                                   connection,
		                                   specific_object,
		                                   subject,
		                                   error);
	}

	return (NMActiveConnection *) nm_act_request_new (connection,
	                                                  specific_object,
	                                                  subject,
	                                                  device);
}

static void
_internal_activation_failed (NMManager *self,
                             NMActiveConnection *active,
                             const char *error_desc)
{
	nm_log_dbg (LOGD_CORE, "Failed to activate '%s': %s",
	            nm_connection_get_id (nm_active_connection_get_connection (active)),
	            error_desc);

	if (nm_active_connection_get_state (active) <= NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		nm_active_connection_set_state (active, NM_ACTIVE_CONNECTION_STATE_DEACTIVATING);
		nm_active_connection_set_state (active, NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);
	}
}

static void
_internal_activation_auth_done (NMActiveConnection *active,
                                gboolean success,
                                const char *error_desc,
                                gpointer user_data1,
                                gpointer user_data2)
{
	NMManager *self = user_data1;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;

	priv->authorizing_connections = g_slist_remove (priv->authorizing_connections, active);

	if (success) {
		if (_internal_activate_generic (self, active, &error)) {
			g_object_unref (active);
			return;
		}
	}

	g_assert (error_desc || error);
	_internal_activation_failed (self, active, error_desc ? error_desc : error->message);
	g_object_unref (active);
	g_clear_error (&error);
}

/**
 * nm_manager_activate_connection():
 * @self: the #NMManager
 * @connection: the #NMConnection to activate on @device
 * @specific_object: the specific object path, if any, for the activation
 * @device: the #NMDevice to activate @connection on
 * @subject: the subject which requested activation
 * @error: return location for an error
 *
 * Begins a new internally-initiated activation of @connection on @device.
 * @subject should be the subject of the activation that triggered this
 * one, or if this is an autoconnect request, a new internal subject.
 * The returned #NMActiveConnection is owned by the Manager and should be
 * referenced by the caller if the caller continues to use it.
 *
 * Returns: (transfer none): the new #NMActiveConnection that tracks
 * activation of @connection on @device
 */
NMActiveConnection *
nm_manager_activate_connection (NMManager *self,
                                NMConnection *connection,
                                const char *specific_object,
                                NMDevice *device,
                                NMAuthSubject *subject,
                                GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *active;
	char *error_desc = NULL;
	GSList *iter;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	/* Ensure the subject has permissions for this connection */
	if (!nm_auth_is_subject_in_acl (connection,
	                                subject,
	                                &error_desc)) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     error_desc);
		g_free (error_desc);
		return NULL;
	}

	/* Look for a active connection that's equivalent and is already pending authorization
	 * and eventual activation. This is used to de-duplicate concurrent activations which would
	 * otherwise race and cause the device to disconnect and reconnect repeatedly.
	 * In particular, this allows the master and multiple slaves to concurrently auto-activate
	 * while all the slaves would use the same active-connection. */
	for (iter = priv->authorizing_connections; iter; iter = g_slist_next (iter)) {
		active = iter->data;

		if (   connection == nm_active_connection_get_connection (active)
		    && g_strcmp0 (nm_active_connection_get_specific_object (active), specific_object) == 0
		    && nm_active_connection_get_device (active) == device
		    && nm_auth_subject_is_internal (nm_active_connection_get_subject (active))
		    && nm_auth_subject_is_internal (subject))
			return active;
	}

	active = _new_active_connection (self,
	                                 connection,
	                                 specific_object,
	                                 device,
	                                 subject,
	                                 error);
	if (active) {
		priv->authorizing_connections = g_slist_prepend (priv->authorizing_connections, active);
		nm_active_connection_authorize (active, _internal_activation_auth_done, self, NULL);
	}
	return active;
}

static NMAuthSubject *
validate_activation_request (NMManager *self,
                             DBusGMethodInvocation *context,
                             NMConnection *connection,
                             const char *device_path,
                             NMDevice **out_device,
                             gboolean *out_vpn,
                             GError **error)
{
	NMDevice *device = NULL;
	gboolean vpn = FALSE;
	NMAuthSubject *subject = NULL;
	char *error_desc = NULL;

	g_assert (connection);
	g_assert (out_device);
	g_assert (out_vpn);

	/* Validate the caller */
	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "Failed to get request UID.");
		return NULL;
	}

	/* Ensure the subject has permissions for this connection */
	if (!nm_auth_is_subject_in_acl (connection,
	                                subject,
	                                &error_desc)) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     error_desc);
		g_free (error_desc);
		goto error;
	}

	/* Not implemented yet, we want to fail early */
	if (   nm_connection_get_setting_connection (connection)
	    && nm_connection_get_setting_ip6_config (connection)
	    && !strcmp (nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG),
	                NM_SETTING_IP6_CONFIG_METHOD_SHARED)) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_CONNECTION_NOT_AVAILABLE,
		                     "Sharing IPv6 connections is not supported yet.");
		return NULL;
	}

	/* Check whether it's a VPN or not */
	if (   nm_connection_get_setting_vpn (connection)
	    || nm_connection_is_type (connection, NM_SETTING_VPN_SETTING_NAME))
		vpn = TRUE;

	/* Normalize device path */
	if (device_path && g_strcmp0 (device_path, "/") == 0)
		device_path = NULL;

	/* And validate it */
	if (device_path) {
		device = nm_manager_get_device_by_path (self, device_path);
		if (!device) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR,
			                     NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                     "Device not found");
			goto error;
		}
	} else
		device = nm_manager_get_best_device_for_connection (self, connection);

	if (!device) {
		gboolean is_software = nm_connection_is_virtual (connection);

		/* VPN and software-device connections don't need a device yet */
		if (!vpn && !is_software) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR,
			                     NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                     "No suitable device found for this connection.");
			goto error;
		}

		if (is_software) {
			char *iface;

			/* Look for an existing device with the connection's interface name */
			iface = get_virtual_iface_name (self, connection, NULL, error);
			if (!iface)
				goto error;

			device = find_device_by_ip_iface (self, iface);
			g_free (iface);
		}
	}

	*out_device = device;
	*out_vpn = vpn;
	return subject;

error:
	g_object_unref (subject);
	return NULL;
}

/***********************************************************************/

static void
_activation_auth_done (NMActiveConnection *active,
                       gboolean success,
                       const char *error_desc,
                       gpointer user_data1,
                       gpointer user_data2)
{
	NMManager *self = user_data1;
	DBusGMethodInvocation *context = user_data2;
	GError *error = NULL;
	NMAuthSubject *subject;
	NMConnection *connection;

	subject = nm_active_connection_get_subject (active);
	connection = nm_active_connection_get_connection (active);

	if (success) {
		if (_internal_activate_generic (self, active, &error)) {
			dbus_g_method_return (context, nm_exported_object_get_path (NM_EXPORTED_OBJECT (active)));
			nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, TRUE,
			                            subject, NULL);
			g_object_unref (active);
			return;
		}
	} else {
		error = g_error_new_literal (NM_MANAGER_ERROR,
			                         NM_MANAGER_ERROR_PERMISSION_DENIED,
			                         error_desc);
	}

	g_assert (error);
	dbus_g_method_return_error (context, error);
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, FALSE,
	                            subject, error->message);
	_internal_activation_failed (self, active, error->message);

	g_object_unref (active);
	g_error_free (error);
}

static void
impl_manager_activate_connection (NMManager *self,
                                  const char *connection_path,
                                  const char *device_path,
                                  const char *specific_object_path,
                                  DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *active = NULL;
	NMAuthSubject *subject = NULL;
	NMConnection *connection = NULL;
	NMDevice *device = NULL;
	gboolean is_vpn = FALSE;
	GError *error = NULL;

	/* Normalize object paths */
	if (g_strcmp0 (connection_path, "/") == 0)
		connection_path = NULL;
	if (g_strcmp0 (specific_object_path, "/") == 0)
		specific_object_path = NULL;
	if (g_strcmp0 (device_path, "/") == 0)
		device_path = NULL;

	/* If the connection path is given and valid, that connection is activated.
	 * Otherwise the "best" connection for the device is chosen and activated,
	 * regardless of whether that connection is autoconnect-enabled or not
	 * (since this is an explicit request, not an auto-activation request).
	 */
	if (!connection_path) {
		GPtrArray *available;
		guint64 best_timestamp = 0;
		guint i;

		/* If no connection is given, find a suitable connection for the given device path */
		if (!device_path) {
			error = g_error_new_literal (NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                             "Only devices may be activated without a specifying a connection");
			goto error;
		}
		device = nm_manager_get_device_by_path (self, device_path);
		if (!device) {
			error = g_error_new (NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                     "Cannot activate unknown device %s", device_path);
			goto error;
		}

		available = nm_device_get_available_connections (device, specific_object_path);
		for (i = 0; available && i < available->len; i++) {
			NMSettingsConnection *candidate = g_ptr_array_index (available, i);
			guint64 candidate_timestamp = 0;

			nm_settings_connection_get_timestamp (candidate, &candidate_timestamp);
			if (!connection_path || (candidate_timestamp > best_timestamp)) {
				connection_path = nm_connection_get_path (NM_CONNECTION (candidate));
				best_timestamp = candidate_timestamp;
			}
		}

		if (available)
			g_ptr_array_free (available, TRUE);

		if (!connection_path) {
			error = g_error_new_literal (NM_MANAGER_ERROR,
			                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
			                             "The device has no connections available.");
			goto error;
		}
	}

	g_assert (connection_path);
	connection = (NMConnection *) nm_settings_get_connection_by_path (priv->settings, connection_path);
	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		                             "Connection could not be found.");
		goto error;
	}

	subject = validate_activation_request (self,
	                                       context,
	                                       connection,
	                                       device_path,
	                                       &device,
	                                       &is_vpn,
	                                       &error);
	if (!subject)
		goto error;

	active = _new_active_connection (self,
	                                 connection,
	                                 specific_object_path,
	                                 device,
	                                 subject,
	                                 &error);
	if (!active)
		goto error;

	nm_active_connection_authorize (active, _activation_auth_done, self, context);
	g_clear_object (&subject);
	return;

error:
	if (connection) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, FALSE,
		                            subject, error->message);
	}
	g_clear_object (&active);
	g_clear_object (&subject);

	g_assert (error);
	dbus_g_method_return_error (context, error);
	g_error_free (error);
}

/***********************************************************************/

typedef struct {
	NMManager *manager;
	NMActiveConnection *active;
} AddAndActivateInfo;

static void
activation_add_done (NMSettings *self,
                     NMSettingsConnection *new_connection,
                     GError *error,
                     DBusGMethodInvocation *context,
                     NMAuthSubject *subject,
                     gpointer user_data)
{
	AddAndActivateInfo *info = user_data;
	GError *local = NULL;

	if (!error) {
		nm_active_connection_set_connection (info->active, NM_CONNECTION (new_connection));

		if (_internal_activate_generic (info->manager, info->active, &local)) {
			nm_settings_connection_commit_changes (new_connection,
			                                       NM_SETTINGS_CONNECTION_COMMIT_REASON_USER_ACTION | NM_SETTINGS_CONNECTION_COMMIT_REASON_ID_CHANGED,
			                                       NULL, NULL);
			dbus_g_method_return (context,
			                      nm_connection_get_path (NM_CONNECTION (new_connection)),
			                      nm_exported_object_get_path (NM_EXPORTED_OBJECT (info->active)));
			nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE,
			                            nm_active_connection_get_connection (info->active),
			                            TRUE,
			                            nm_active_connection_get_subject (info->active),
			                            NULL);
			goto done;
		}
		error = local;
	}

	g_assert (error);
	_internal_activation_failed (info->manager, info->active, error->message);
	nm_settings_connection_delete (new_connection, NULL, NULL);
	dbus_g_method_return_error (context, error);
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE,
	                            nm_active_connection_get_connection (info->active),
	                            FALSE,
	                            nm_active_connection_get_subject (info->active),
	                            error->message);
	g_clear_error (&local);

done:
	g_object_unref (info->active);
	g_free (info);
}

static void
_add_and_activate_auth_done (NMActiveConnection *active,
                             gboolean success,
                             const char *error_desc,
                             gpointer user_data1,
                             gpointer user_data2)
{
	NMManager *self = user_data1;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	DBusGMethodInvocation *context = user_data2;
	AddAndActivateInfo *info;
	GError *error = NULL;

	if (success) {
		info = g_malloc0 (sizeof (*info));
		info->manager = self;
		info->active = g_object_ref (active);

		/* Basic sender auth checks performed; try to add the connection */
		nm_settings_add_connection_dbus (priv->settings,
		                                 nm_active_connection_get_connection (active),
		                                 FALSE,
		                                 context,
		                                 activation_add_done,
		                                 info);
	} else {
		g_assert (error_desc);
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		dbus_g_method_return_error (context, error);
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE,
		                            nm_active_connection_get_connection (active),
		                            FALSE,
		                            nm_active_connection_get_subject (active),
		                            error->message);
		g_error_free (error);
	}

	g_object_unref (active);
}

static void
impl_manager_add_and_activate_connection (NMManager *self,
                                          GHashTable *settings,
                                          const char *device_path,
                                          const char *specific_object_path,
                                          DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMConnection *connection = NULL;
	GSList *all_connections = NULL;
	NMActiveConnection *active = NULL;
	NMAuthSubject *subject = NULL;
	GError *error = NULL;
	NMDevice *device = NULL;
	gboolean vpn = FALSE;

	/* Normalize object paths */
	if (g_strcmp0 (specific_object_path, "/") == 0)
		specific_object_path = NULL;
	if (g_strcmp0 (device_path, "/") == 0)
		device_path = NULL;

	/* Try to create a new connection with the given settings.
	 * We allow empty settings for AddAndActivateConnection(). In that case,
	 * the connection will be completed in nm_utils_complete_generic() or
	 * nm_device_complete_connection() below. Just make sure we don't expect
	 * specific data being in the connection till then (especially in
	 * validate_activation_request()).
	 */
	connection = nm_simple_connection_new ();
	if (settings && g_hash_table_size (settings)) {
		GVariant *settings_dict = nm_utils_connection_hash_to_dict (settings);

		nm_connection_replace_settings (connection, settings_dict, NULL);
		g_variant_unref (settings_dict);
	}

	subject = validate_activation_request (self,
	                                       context,
	                                       connection,
	                                       device_path,
	                                       &device,
	                                       &vpn,
	                                       &error);
	if (!subject)
		goto error;

	/* AddAndActivate() requires a device to complete the connection with */
	if (!device) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		                             "This connection requires an existing device.");
		goto error;
	}

	all_connections = nm_settings_get_connections (priv->settings);
	if (vpn) {
		/* Try to fill the VPN's connection setting and name at least */
		if (!nm_connection_get_setting_vpn (connection)) {
			error = g_error_new_literal (NM_CONNECTION_ERROR,
			                             NM_CONNECTION_ERROR_MISSING_SETTING,
			                             "VPN connections require a 'vpn' setting");
			g_prefix_error (&error, "%s: ", NM_SETTING_VPN_SETTING_NAME);
			goto error;
		}

		nm_utils_complete_generic (connection,
		                           NM_SETTING_VPN_SETTING_NAME,
		                           all_connections,
		                           NULL,
		                           _("VPN connection"),
		                           NULL,
		                           FALSE); /* No IPv6 by default for now */
	} else {
		/* Let each device subclass complete the connection */
		if (!nm_device_complete_connection (device,
		                                    connection,
		                                    specific_object_path,
		                                    all_connections,
		                                    &error))
			goto error;
	}
	g_slist_free (all_connections);
	all_connections = NULL;

	active = _new_active_connection (self,
	                                 connection,
	                                 specific_object_path,
	                                 device,
	                                 subject,
	                                 &error);
	if (!active)
		goto error;

	nm_active_connection_authorize (active, _add_and_activate_auth_done, self, context);
	g_object_unref (connection);
	g_object_unref (subject);
	return;

error:
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE, connection, FALSE, subject, error->message);
	g_clear_object (&connection);
	g_slist_free (all_connections);
	g_clear_object (&subject);
	g_clear_object (&active);

	g_assert (error);
	dbus_g_method_return_error (context, error);
	g_error_free (error);
}

/***********************************************************************/

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
		NMVpnConnectionStateReason vpn_reason = NM_VPN_CONNECTION_STATE_REASON_USER_DISCONNECTED;

		if (reason == NM_DEVICE_STATE_REASON_CONNECTION_REMOVED)
			vpn_reason = NM_VPN_CONNECTION_STATE_REASON_CONNECTION_REMOVED;
		if (nm_vpn_manager_deactivate_connection (priv->vpn_manager, NM_VPN_CONNECTION (active), vpn_reason))
			success = TRUE;
		else
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
			                     "The VPN connection was not active.");
	} else {
		g_assert (NM_IS_ACT_REQUEST (active));
		nm_device_state_changed (nm_active_connection_get_device (active),
		                         NM_DEVICE_STATE_DEACTIVATING,
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
	NMActiveConnection *active;
	char *path;

	g_assert (context);

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	path = nm_auth_chain_get_data (chain, "path");
	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL);
	active = active_connection_get_by_path (self, path);

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
		                                       path,
		                                       NM_DEVICE_STATE_REASON_USER_REQUESTED,
		                                       &error))
			g_assert (error);
	}

	if (error)
		dbus_g_method_return_error (context, error);
	else
		dbus_g_method_return (context);

	if (active) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DEACTIVATE,
		                            nm_active_connection_get_connection (active),
		                            !error,
		                            nm_auth_chain_get_subject (chain),
		                            error ? error->message : NULL);
	}

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
	NMAuthSubject *subject = NULL;
	GSList *iter;
	NMAuthChain *chain;
	char *error_desc = NULL;

	/* Find the connection by its object path */
	for (iter = priv->active_connections; iter; iter = g_slist_next (iter)) {
		NMActiveConnection *ac = iter->data;

		if (g_strcmp0 (nm_exported_object_get_path (NM_EXPORTED_OBJECT (ac)), active_path) == 0) {
			connection = nm_active_connection_get_connection (ac);
			break;
		}
	}

	if (!connection) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
		                             "The connection was not active.");
		goto done;
	}

	/* Validate the caller */
	subject = nm_auth_subject_new_unix_process_from_context (context);
	if (!subject) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Failed to get request UID.");
		goto done;
	}

	/* Ensure the subject has permissions for this connection */
	if (!nm_auth_is_subject_in_acl (connection,
	                                subject,
	                                &error_desc)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		g_free (error_desc);
		goto done;
	}

	/* Validate the user request */
	chain = nm_auth_chain_new_subject (subject, context, deactivate_net_auth_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		goto done;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "path", g_strdup (active_path), g_free);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);

done:
	if (error) {
		dbus_g_method_return_error (context, error);
		if (connection) {
			nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DEACTIVATE, connection, FALSE,
			                            subject, error->message);
		}
	}
	g_clear_object (&subject);
	g_clear_error (&error);
}

static gboolean
device_is_wake_on_lan (NMDevice *device)
{
	return nm_platform_link_get_wake_on_lan (NM_PLATFORM_GET, nm_device_get_ip_ifindex (device));
}

static void
do_sleep_wake (NMManager *self, gboolean sleeping_changed)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean suspending, waking_from_suspend;
	GSList *iter;

	suspending = sleeping_changed && priv->sleeping;
	waking_from_suspend = sleeping_changed && !priv->sleeping;

	if (manager_sleeping (self)) {
		nm_log_info (LOGD_SUSPEND, "%s...", suspending ? "sleeping" : "disabling");

		/* FIXME: are there still hardware devices that need to be disabled around
		 * suspend/resume?
		 */
		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *device = iter->data;

			/* FIXME: shouldn't we be unmanaging software devices if !suspending? */
			if (nm_device_is_software (device))
				continue;
			/* Wake-on-LAN devices will be taken down post-suspend rather than pre- */
			if (suspending && device_is_wake_on_lan (device))
				continue;

			nm_device_set_unmanaged (device, NM_UNMANAGED_INTERNAL, TRUE, NM_DEVICE_STATE_REASON_SLEEPING);
		}
	} else {
		nm_log_info (LOGD_SUSPEND, "%s...", waking_from_suspend ? "waking up" : "re-enabling");

		if (waking_from_suspend) {
			/* Belatedly take down Wake-on-LAN devices; ideally we wouldn't have to do this
			 * but for now it's the only way to make sure we re-check their connectivity.
			 */
			for (iter = priv->devices; iter; iter = iter->next) {
				NMDevice *device = iter->data;

				if (nm_device_is_software (device))
					continue;
				if (device_is_wake_on_lan (device))
					nm_device_set_unmanaged (device, NM_UNMANAGED_INTERNAL, TRUE, NM_DEVICE_STATE_REASON_SLEEPING);
			}
		}

		/* Ensure rfkill state is up-to-date since we don't respond to state
		 * changes during sleep.
		 */
		nm_manager_rfkill_update (self, RFKILL_TYPE_UNKNOWN);

		/* Re-manage managed devices */
		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *device = NM_DEVICE (iter->data);
			guint i;

			if (nm_device_is_software (device))
				continue;

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

			nm_device_set_unmanaged (device, NM_UNMANAGED_INTERNAL, FALSE, NM_DEVICE_STATE_REASON_NOW_MANAGED);
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

	do_sleep_wake (self, TRUE);

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
	gs_unref_object NMAuthSubject *subject = NULL;
#if 0
	NMAuthChain *chain;
	const char *error_desc = NULL;
#endif

	g_return_if_fail (NM_IS_MANAGER (self));

	priv = NM_MANAGER_GET_PRIVATE (self);
	subject = nm_auth_subject_new_unix_process_from_context (context);

	if (priv->sleeping == do_sleep) {
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,
		                     "Already %s", do_sleep ? "asleep" : "awake");
		dbus_g_method_return_error (context, error);
		nm_audit_log_control_op (NM_AUDIT_OP_SLEEP_CONTROL, do_sleep ? "on" : "off", FALSE, subject,
		                         error->message);
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
	nm_audit_log_control_op (NM_AUDIT_OP_SLEEP_CONTROL, do_sleep ? "on" : "off", TRUE, subject, NULL);
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
sleeping_cb (NMSleepMonitor *monitor, gpointer user_data)
{
	nm_log_dbg (LOGD_SUSPEND, "Received sleeping signal");
	_internal_sleep (NM_MANAGER (user_data), TRUE);
}

static void
resuming_cb (NMSleepMonitor *monitor, gpointer user_data)
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

	do_sleep_wake (self, FALSE);

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
	NMAuthSubject *subject;

	g_assert (context);

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);
	enable = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "enable"));
	subject = nm_auth_chain_get_subject (chain);

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
		_internal_enable (self, enable);
		dbus_g_method_return (context);
		nm_audit_log_control_op (NM_AUDIT_OP_NET_CONTROL, enable ? "on" : "off", TRUE,
		                         subject, NULL);
	}

	if (ret_error) {
		dbus_g_method_return_error (context, ret_error);
		nm_audit_log_control_op (NM_AUDIT_OP_NET_CONTROL, enable ? "on" : "off", FALSE,
		                         subject, ret_error->message);
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

	g_return_if_fail (NM_IS_MANAGER (self));

	priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->net_enabled == enable) {
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED,
		                     "Already %s", enable ? "enabled" : "disabled");
		goto done;
	}

	chain = nm_auth_chain_new_context (context, enable_net_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		goto done;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "enable", GUINT_TO_POINTER (enable), NULL);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK, TRUE);

done:
	if (error)
		dbus_g_method_return_error (context, error);
	g_clear_error (&error);
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

	g_assert (context);

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
	GError *error = NULL;

	chain = nm_auth_chain_new_context (context, get_permissions_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return;
	}

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

static void
impl_manager_set_logging (NMManager *manager,
                          const char *level,
                          const char *domains,
                          DBusGMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GError *error = NULL;
	gulong caller_uid = G_MAXULONG;

	if (!nm_bus_manager_get_caller_info (priv->dbus_mgr, context, NULL, &caller_uid, NULL)) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Failed to get request UID.");
		goto done;
	}

	if (0 != caller_uid) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Permission denied");
		goto done;
	}

	if (nm_logging_setup (level, domains, NULL, &error)) {
		nm_log_info (LOGD_CORE, "logging: level '%s' domains '%s'",
		             nm_logging_level_to_string (), nm_logging_domains_to_string ());
	}

done:
	if (error) {
		dbus_g_method_return_error (context, error);
		g_error_free (error);
	} else
		dbus_g_method_return (context);
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
	GError *error = NULL;

	/* Validate the request */
	chain = nm_auth_chain_new_context (context, check_connectivity_auth_done_cb, manager);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		dbus_g_method_return_error (context, error);
		g_clear_error (&error);
		return;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);
}

static void
start_factory (NMDeviceFactory *factory, gpointer user_data)
{
	nm_device_factory_start (factory);
}

void
nm_manager_start (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	guint i;

	/* Set initial radio enabled/disabled state */
	for (i = 0; i < RFKILL_TYPE_MAX; i++) {
		RadioState *rstate = &priv->radio_states[i];
		gboolean enabled;

		if (!rstate->desc)
			continue;

		/* recheck kernel rfkill state */
		update_rstate_from_rfkill (priv->rfkill_mgr, rstate);

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

	/* Start device factories */
	nm_device_factory_manager_for_each_factory (start_factory, NULL);

	platform_query_devices (self);

	/*
	 * Connections added before the manager is started do not emit
	 * connection-added signals thus devices have to be created manually.
	 */
	system_create_virtual_devices (self);

	check_if_startup_complete (self);
}

void
nm_manager_stop (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	/* Remove all devices */
	while (priv->devices)
		remove_device (self, NM_DEVICE (priv->devices->data), TRUE, TRUE);
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

	nm_log_dbg (LOGD_CORE, "connectivity checking indicates %s",
	            nm_connectivity_state_to_string (nm_connectivity_get_state (connectivity)));

	nm_manager_update_state (self);
	g_object_notify (G_OBJECT (self), NM_MANAGER_CONNECTIVITY);
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
connection_metered_changed (GObject *object,
                            NMMetered metered,
                            gpointer user_data)
{
	nm_manager_update_metered (NM_MANAGER (user_data));
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
		if (priv->primary_connection) {
			g_signal_handlers_disconnect_by_func (priv->primary_connection,
			                                      G_CALLBACK (connection_metered_changed),
			                                      self);
			g_clear_object (&priv->primary_connection);
		}

		priv->primary_connection = ac ? g_object_ref (ac) : NULL;

		if (priv->primary_connection) {
			g_signal_connect (priv->primary_connection, NM_ACTIVE_CONNECTION_DEVICE_METERED_CHANGED,
			                  G_CALLBACK (connection_metered_changed), self);
		}
		nm_log_dbg (LOGD_CORE, "PrimaryConnection now %s", ac ? nm_active_connection_get_id (ac) : "(none)");
		g_object_notify (G_OBJECT (self), NM_MANAGER_PRIMARY_CONNECTION);
		g_object_notify (G_OBJECT (self), NM_MANAGER_PRIMARY_CONNECTION_TYPE);
		nm_manager_update_metered (self);
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
		nm_log_dbg (LOGD_CORE, "ActivatingConnection now %s", ac ? nm_active_connection_get_id (ac) : "(none)");
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
	const char *permission, *prop, *audit_op;
	GObject *obj;
	gboolean set_enabled = TRUE;
	NMAuthSubject *subject;
	gs_free char *prop_value = NULL;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	message = nm_auth_chain_get_data (chain, "message");
	permission = nm_auth_chain_get_data (chain, "permission");
	prop = nm_auth_chain_get_data (chain, "prop");
	set_enabled = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "enabled"));
	obj = nm_auth_chain_get_data (chain, "object");
	audit_op = nm_auth_chain_get_data (chain, "audit-op");

	prop_value = g_strdup_printf ("%s:%d", prop, set_enabled);

	result = nm_auth_chain_get_result (chain, permission);
	subject = nm_auth_chain_get_subject (chain);
	if (error || (result != NM_AUTH_CALL_RESULT_YES)) {
		reply = dbus_message_new_error (message,
		                                NM_IS_DEVICE (obj) ? DEV_PERM_DENIED_ERROR : NM_PERM_DENIED_ERROR,
		                                "Not authorized to perform this operation");
		nm_audit_log_control_op (audit_op, prop_value, FALSE, subject, error ? error->message : NULL);
	} else {
		g_object_set (obj, prop, set_enabled, NULL);
		reply = dbus_message_new_method_return (message);
		nm_audit_log_control_op (audit_op, prop_value, TRUE, subject, NULL);
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
	DBusMessage *reply = NULL;
	gboolean set_enabled = FALSE;
	NMAuthSubject *subject = NULL;
	NMAuthChain *chain;
	GObject *obj;
	const char *audit_op = NULL;

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
		audit_op = NM_AUDIT_OP_RADIO_CONTROL;
	} else if (!strcmp (propname, "WwanEnabled")) {
		glib_propname = NM_MANAGER_WWAN_ENABLED;
		permission = NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN;
		audit_op = NM_AUDIT_OP_RADIO_CONTROL;
	} else if (!strcmp (propname, "WimaxEnabled")) {
		glib_propname = NM_MANAGER_WIMAX_ENABLED;
		permission = NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX;
		audit_op = NM_AUDIT_OP_RADIO_CONTROL;
	} else if (!strcmp (propname, "Autoconnect")) {
		glib_propname = NM_DEVICE_AUTOCONNECT;
		permission = NM_AUTH_PERMISSION_NETWORK_CONTROL;
		audit_op = NM_AUDIT_OP_DEVICE_AUTOCONNECT;
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

	subject = nm_auth_subject_new_unix_process_from_message (connection, message);
	if (!subject) {
		reply = dbus_message_new_error (message, NM_PERM_DENIED_ERROR,
		                                "Could not determine request UID.");
		goto out;
	}

	/* Validate the user request */
	chain = nm_auth_chain_new_subject (subject, NULL, prop_set_auth_done_cb, self);
	if (!chain) {
		reply = dbus_message_new_error (message, NM_PERM_DENIED_ERROR,
		                                "Could not authenticate request.");
		goto out;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "prop", g_strdup (glib_propname), g_free);
	nm_auth_chain_set_data (chain, "permission", g_strdup (permission), g_free);
	nm_auth_chain_set_data (chain, "enabled", GUINT_TO_POINTER (set_enabled), NULL);
	nm_auth_chain_set_data (chain, "message", dbus_message_ref (message), (GDestroyNotify) dbus_message_unref);
	nm_auth_chain_set_data (chain, "connection", dbus_connection_ref (connection), (GDestroyNotify) dbus_connection_unref);
	nm_auth_chain_set_data (chain, "object", g_object_ref (obj), (GDestroyNotify) g_object_unref);
	nm_auth_chain_set_data (chain, "audit-op", (char *) audit_op, NULL);
	nm_auth_chain_add_call (chain, permission, TRUE);

out:
	if (reply) {
		dbus_connection_send (connection, reply, NULL);
		dbus_message_unref (reply);
	}
	g_clear_object (&subject);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static void
authority_changed_cb (NMAuthManager *auth_manager, gpointer user_data)
{
	/* Let clients know they should re-check their authorization */
	g_signal_emit (NM_MANAGER (user_data), signals[CHECK_PERMISSIONS], 0);
}

#define KERN_RFKILL_OP_CHANGE_ALL 3
#define KERN_RFKILL_TYPE_WLAN     1
#define KERN_RFKILL_TYPE_WWAN     5
struct rfkill_event {
	__u32 idx;
	__u8  type;
	__u8  op;
	__u8  soft, hard;
} __attribute__((packed));

static void
rfkill_change (const char *desc, RfKillType rtype, gboolean enabled)
{
	int fd;
	struct rfkill_event event;
	ssize_t len;

	g_return_if_fail (rtype == RFKILL_TYPE_WLAN || rtype == RFKILL_TYPE_WWAN);

	errno = 0;
	fd = open ("/dev/rfkill", O_RDWR);
	if (fd < 0) {
		if (errno == EACCES)
			nm_log_warn (LOGD_RFKILL, "(%s): failed to open killswitch device", desc);
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
	switch (rtype) {
	case RFKILL_TYPE_WLAN:
		event.type = KERN_RFKILL_TYPE_WLAN;
		break;
	case RFKILL_TYPE_WWAN:
		event.type = KERN_RFKILL_TYPE_WWAN;
		break;
	default:
		g_assert_not_reached ();
	}
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

	/* Don't touch devices if asleep/networking disabled */
	if (manager_sleeping (self))
		return;

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
		/* Try to change the kernel rfkill state */
		if (rstate->rtype == RFKILL_TYPE_WLAN || rstate->rtype == RFKILL_TYPE_WWAN)
			rfkill_change (rstate->desc, rstate->rtype, new_enabled);

		manager_update_radio_enabled (self, rstate, new_enabled);
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
dbus_connection_changed_cb (NMBusManager *dbus_mgr,
                            DBusConnection *dbus_connection,
                            gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	gboolean success = FALSE;

	if (dbus_connection) {
		/* Register property filter on new connection; there's no reason this
		 * should fail except out-of-memory or program error; if it does fail
		 * then there's no Manager property access control, which is bad.
		 */
		success = dbus_connection_add_filter (dbus_connection, prop_filter, self, NULL);
		g_assert (success);
	}
	NM_MANAGER_GET_PRIVATE (self)->prop_filter_added = success;
}

/**********************************************************************/

static NMManager *singleton = NULL;

NMManager *
nm_manager_get (void)
{
	g_assert (singleton);
	return singleton;
}

NMConnectionProvider *
nm_connection_provider_get (void)
{
	g_assert (singleton);
	g_assert (NM_MANAGER_GET_PRIVATE (singleton)->settings);
	return NM_CONNECTION_PROVIDER (NM_MANAGER_GET_PRIVATE (singleton)->settings);
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
	NMConfigData *config_data;

	g_assert (settings);

	/* Can only be called once */
	g_assert (singleton == NULL);
	singleton = (NMManager *) g_object_new (NM_TYPE_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_MANAGER_GET_PRIVATE (singleton);

	bus = nm_bus_manager_get_connection (priv->dbus_mgr);
	if (!bus) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		                     "Failed to initialize D-Bus connection");
		g_object_unref (singleton);
		return NULL;
	}

	dbus_connection = dbus_g_connection_get_connection (bus);
	g_assert (dbus_connection);

	priv->policy = nm_policy_new (singleton, settings);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP4_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), singleton);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP6_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), singleton);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP4_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), singleton);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP6_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), singleton);

	priv->config = g_object_ref (nm_config_get ());
	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (_config_changed_cb),
	                  singleton);

	config_data = nm_config_get_data (priv->config);
	priv->connectivity = nm_connectivity_new (nm_config_data_get_connectivity_uri (config_data),
	                                          nm_config_data_get_connectivity_interval (config_data),
	                                          nm_config_data_get_connectivity_response (config_data));
	g_signal_connect (priv->connectivity, "notify::" NM_CONNECTIVITY_STATE,
	                  G_CALLBACK (connectivity_changed), singleton);

	if (!dbus_connection_add_filter (dbus_connection, prop_filter, singleton, NULL)) {
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		                     "Failed to register DBus connection filter");
		g_object_unref (singleton);
		return NULL;
	}
	priv->prop_filter_added = TRUE;

	priv->settings = g_object_ref (settings);
	g_signal_connect (priv->settings, "notify::" NM_SETTINGS_STARTUP_COMPLETE,
	                  G_CALLBACK (settings_startup_complete_changed), singleton);

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

	nm_exported_object_export (NM_EXPORTED_OBJECT (singleton));

	g_signal_connect (nm_platform_get (),
	                  NM_PLATFORM_SIGNAL_LINK_CHANGED,
	                  G_CALLBACK (platform_link_cb),
	                  singleton);

	priv->rfkill_mgr = nm_rfkill_manager_new ();
	g_signal_connect (priv->rfkill_mgr,
	                  "rfkill-changed",
	                  G_CALLBACK (rfkill_manager_rfkill_changed_cb),
	                  singleton);

	/* Force kernel WiFi/WWAN rfkill state to follow NM saved WiFi/WWAN state
	 * in case the BIOS doesn't save rfkill state, and to be consistent with user
	 * changes to the WirelessEnabled/WWANEnabled properties which toggle kernel
	 * rfkill.
	 */
	rfkill_change (priv->radio_states[RFKILL_TYPE_WLAN].desc, RFKILL_TYPE_WLAN, initial_wifi_enabled);
	rfkill_change (priv->radio_states[RFKILL_TYPE_WWAN].desc, RFKILL_TYPE_WWAN, initial_wwan_enabled);

	nm_device_factory_manager_load_factories (_register_device_factory, singleton);

	return singleton;
}

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	guint i;
	GFile *file;

	/* Initialize rfkill structures and states */
	memset (priv->radio_states, 0, sizeof (priv->radio_states));

	priv->radio_states[RFKILL_TYPE_WLAN].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WLAN].key = "WirelessEnabled";
	priv->radio_states[RFKILL_TYPE_WLAN].prop = NM_MANAGER_WIRELESS_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].hw_prop = NM_MANAGER_WIRELESS_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].desc = "WiFi";
	priv->radio_states[RFKILL_TYPE_WLAN].rtype = RFKILL_TYPE_WLAN;

	priv->radio_states[RFKILL_TYPE_WWAN].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WWAN].key = "WWANEnabled";
	priv->radio_states[RFKILL_TYPE_WWAN].prop = NM_MANAGER_WWAN_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].hw_prop = NM_MANAGER_WWAN_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].desc = "WWAN";
	priv->radio_states[RFKILL_TYPE_WWAN].rtype = RFKILL_TYPE_WWAN;

	priv->radio_states[RFKILL_TYPE_WIMAX].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WIMAX].key = "WimaxEnabled";
	priv->radio_states[RFKILL_TYPE_WIMAX].prop = NM_MANAGER_WIMAX_ENABLED;
	priv->radio_states[RFKILL_TYPE_WIMAX].hw_prop = NM_MANAGER_WIMAX_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WIMAX].desc = "WiMAX";
	priv->radio_states[RFKILL_TYPE_WIMAX].rtype = RFKILL_TYPE_WIMAX;

	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		priv->radio_states[i].hw_enabled = TRUE;

	priv->sleeping = FALSE;
	priv->state = NM_STATE_DISCONNECTED;
	priv->startup = TRUE;

	priv->dbus_mgr = nm_bus_manager_get ();
	g_signal_connect (priv->dbus_mgr,
	                  NM_BUS_MANAGER_DBUS_CONNECTION_CHANGED,
	                  G_CALLBACK (dbus_connection_changed_cb),
	                  manager);

	priv->vpn_manager = g_object_ref (nm_vpn_manager_get ());

	/* sleep/wake handling */
	priv->sleep_monitor = g_object_ref (nm_sleep_monitor_get ());
	g_signal_connect (priv->sleep_monitor, NM_SLEEP_MONITOR_SLEEPING,
	                  G_CALLBACK (sleeping_cb), manager);
	g_signal_connect (priv->sleep_monitor, NM_SLEEP_MONITOR_RESUMING,
	                  G_CALLBACK (resuming_cb), manager);

	/* Listen for authorization changes */
	g_signal_connect (nm_auth_manager_get (),
	                  NM_AUTH_MANAGER_SIGNAL_CHANGED,
	                  G_CALLBACK (authority_changed_cb),
	                  manager);


	/* Monitor the firmware directory */
	if (strlen (KERNEL_FIRMWARE_DIR)) {
		file = g_file_new_for_path (KERNEL_FIRMWARE_DIR "/");
		priv->fw_monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
		g_object_unref (file);
	}

	if (priv->fw_monitor) {
		g_signal_connect (priv->fw_monitor, "changed",
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

	priv->metered = NM_METERED_UNKNOWN;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMManager *self = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const char *type;

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
		nm_utils_g_value_set_object_path_array (value, priv->active_connections);
		break;
	case PROP_CONNECTIVITY:
		g_value_set_uint (value, nm_connectivity_get_state (priv->connectivity));
		break;
	case PROP_PRIMARY_CONNECTION:
		nm_utils_g_value_set_object_path (value, priv->primary_connection);
		break;
	case PROP_PRIMARY_CONNECTION_TYPE:
		type = priv->primary_connection ? nm_active_connection_get_connection_type (priv->primary_connection) : NULL;
		g_value_set_string (value, type ? type : "");
		break;
	case PROP_ACTIVATING_CONNECTION:
		nm_utils_g_value_set_object_path (value, priv->activating_connection);
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, priv->hostname);
		break;
	case PROP_SLEEPING:
		g_value_set_boolean (value, priv->sleeping);
		break;
	case PROP_DEVICES:
		nm_utils_g_value_set_object_path_array (value, priv->devices);
		break;
	case PROP_METERED:
		g_value_set_uint (value, priv->metered);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
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
_deinit_device_factory (NMDeviceFactory *factory, gpointer user_data)
{
	g_signal_handlers_disconnect_matched (factory, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, NM_MANAGER (user_data));
}

static void
dispose (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *bus;
	DBusConnection *dbus_connection;

	g_slist_free_full (priv->auth_chains, (GDestroyNotify) nm_auth_chain_unref);
	priv->auth_chains = NULL;

	g_signal_handlers_disconnect_by_func (nm_auth_manager_get (),
	                                      G_CALLBACK (authority_changed_cb),
	                                      manager);

	g_assert (priv->devices == NULL);

	if (priv->ac_cleanup_id) {
		g_source_remove (priv->ac_cleanup_id);
		priv->ac_cleanup_id = 0;
	}

	while (priv->active_connections)
		active_connection_remove (manager, NM_ACTIVE_CONNECTION (priv->active_connections->data));
	g_clear_pointer (&priv->active_connections, g_slist_free);
	g_clear_object (&priv->primary_connection);
	g_clear_object (&priv->activating_connection);

	if (priv->config) {
		g_signal_handlers_disconnect_by_func (priv->config, _config_changed_cb, manager);
		g_clear_object (&priv->config);
	}
	if (priv->connectivity) {
		g_signal_handlers_disconnect_by_func (priv->connectivity, connectivity_changed, manager);
		g_clear_object (&priv->connectivity);
	}

	g_free (priv->hostname);

	if (priv->policy) {
		g_signal_handlers_disconnect_by_func (priv->policy, policy_default_device_changed, manager);
		g_signal_handlers_disconnect_by_func (priv->policy, policy_activating_device_changed, manager);
		g_clear_object (&priv->policy);
	}

	g_clear_object (&priv->settings);
	g_free (priv->state_file);
	g_clear_object (&priv->vpn_manager);

	/* Unregister property filter */
	if (priv->dbus_mgr) {
		bus = nm_bus_manager_get_connection (priv->dbus_mgr);
		if (bus) {
			dbus_connection = dbus_g_connection_get_connection (bus);
			if (dbus_connection && priv->prop_filter_added) {
				dbus_connection_remove_filter (dbus_connection, prop_filter, manager);
				priv->prop_filter_added = FALSE;
			}
		}
		g_signal_handlers_disconnect_by_func (priv->dbus_mgr, dbus_connection_changed_cb, manager);
		priv->dbus_mgr = NULL;
	}

	if (priv->sleep_monitor) {
		g_signal_handlers_disconnect_by_func (priv->sleep_monitor, sleeping_cb, manager);
		g_signal_handlers_disconnect_by_func (priv->sleep_monitor, resuming_cb, manager);
		g_clear_object (&priv->sleep_monitor);
	}

	if (priv->fw_monitor) {
		g_signal_handlers_disconnect_by_func (priv->fw_monitor, firmware_dir_changed, manager);

		if (priv->fw_changed_id) {
			g_source_remove (priv->fw_changed_id);
			priv->fw_changed_id = 0;
		}

		g_file_monitor_cancel (priv->fw_monitor);
		g_clear_object (&priv->fw_monitor);
	}

	nm_device_factory_manager_for_each_factory (_deinit_device_factory, manager);
	
	if (priv->timestamp_update_id) {
		g_source_remove (priv->timestamp_update_id);
		priv->timestamp_update_id = 0;
	}

	G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
}

static void
nm_manager_class_init (NMManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMManagerPrivate));

	exported_object_class->export_path = NM_DBUS_PATH;

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_VERSION,
		 g_param_spec_string (NM_MANAGER_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_MANAGER_STATE, "", "",
		                    0, NM_STATE_DISCONNECTED, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_STARTUP,
		 g_param_spec_boolean (NM_MANAGER_STARTUP, "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_NETWORKING_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_NETWORKING_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIRELESS_ENABLED, "", "",
		                       TRUE,
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
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_WWAN_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WWAN_HARDWARE_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_WIMAX_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIMAX_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_WIMAX_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIMAX_HARDWARE_ENABLED, "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTIONS,
		 g_param_spec_boxed (NM_MANAGER_ACTIVE_CONNECTIONS, "", "",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CONNECTIVITY,
		 g_param_spec_uint (NM_MANAGER_CONNECTIVITY, "", "",
		                    NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION,
		 g_param_spec_boxed (NM_MANAGER_PRIMARY_CONNECTION, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PRIMARY_CONNECTION_TYPE,
		 g_param_spec_string (NM_MANAGER_PRIMARY_CONNECTION_TYPE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));


	g_object_class_install_property
		(object_class, PROP_ACTIVATING_CONNECTION,
		 g_param_spec_boxed (NM_MANAGER_ACTIVATING_CONNECTION, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* Hostname is not exported over D-Bus */
	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_MANAGER_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/* Sleeping is not exported over D-Bus */
	g_object_class_install_property
		(object_class, PROP_SLEEPING,
		 g_param_spec_boolean (NM_MANAGER_SLEEPING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_MANAGER_DEVICES, "", "",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
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

	signals[CONFIGURE_QUIT] =
		g_signal_new (NM_MANAGER_CONFIGURE_QUIT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              0, NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (manager_class),
	                                        &dbus_glib_nm_manager_object_info);

	dbus_g_error_domain_register (NM_MANAGER_ERROR, NM_DBUS_INTERFACE, NM_TYPE_MANAGER_ERROR);
}

