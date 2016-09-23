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

#include "nm-default.h"

#include "nm-manager.h"

#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "nm-common-macros.h"
#include "nm-bus-manager.h"
#include "nm-vpn-manager.h"
#include "nm-device.h"
#include "nm-device-generic.h"
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
#include "nm-session-monitor.h"
#include "nm-activation-request.h"
#include "nm-core-internal.h"
#include "nm-config.h"
#include "nm-audit-manager.h"
#include "nm-dbus-compat.h"
#include "nm-checkpoint.h"
#include "nm-checkpoint-manager.h"
#include "NetworkManagerUtils.h"

#include "nmdbus-manager.h"
#include "nmdbus-device.h"

static gboolean add_device (NMManager *self, NMDevice *device, GError **error);

static NMActiveConnection *_new_active_connection (NMManager *self,
                                                   NMConnection *connection,
                                                   const char *specific_object,
                                                   NMDevice *device,
                                                   NMAuthSubject *subject,
                                                   GError **error);

static void policy_activating_device_changed (GObject *object, GParamSpec *pspec, gpointer user_data);

static gboolean find_master (NMManager *self,
                             NMConnection *connection,
                             NMDevice *device,
                             NMSettingsConnection **out_master_connection,
                             NMDevice **out_master_device,
                             NMActiveConnection **out_master_ac,
                             GError **error);

static void nm_manager_update_state (NMManager *manager);

static void connection_changed (NMManager *self, NMConnection *connection);
static void device_sleep_cb (NMDevice *device,
                             GParamSpec *pspec,
                             NMManager *self);

#define TAG_ACTIVE_CONNETION_ADD_AND_ACTIVATE "act-con-add-and-activate"

typedef struct {
	gboolean user_enabled;
	gboolean sw_enabled;
	gboolean hw_enabled;
	RfKillType rtype;
	NMConfigRunStatePropertyType key;
	const char *desc;
	const char *prop;
	const char *hw_prop;
} RadioState;

typedef struct {
	GArray *capabilities;

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
	struct {
		GDBusConnection *connection;
		guint            id;
	} prop_filter;
	NMRfkillManager *rfkill_mgr;

	NMCheckpointManager *checkpoint_mgr;

	NMSettings *settings;
	char *hostname;

	RadioState radio_states[RFKILL_TYPE_MAX];
	gboolean sleeping;
	gboolean net_enabled;

	NMVpnManager *vpn_manager;

	NMSleepMonitor *sleep_monitor;

	NMAuthManager *auth_mgr;

	GSList *auth_chains;
	GHashTable *sleep_devices;

	/* Firmware dir monitor */
	GFileMonitor *fw_monitor;
	guint fw_changed_id;

	guint timestamp_update_id;

	gboolean startup;
	gboolean devices_inited;
} NMManagerPrivate;

struct _NMManager {
	NMExportedObject parent;
	NMManagerPrivate _priv;
};

typedef struct {
	NMExportedObjectClass parent;
} NMManagerClass;

G_DEFINE_TYPE (NMManager, nm_manager, NM_TYPE_EXPORTED_OBJECT)

#define NM_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMManager, NM_IS_MANAGER)

enum {
	DEVICE_ADDED,
	INTERNAL_DEVICE_ADDED,
	DEVICE_REMOVED,
	INTERNAL_DEVICE_REMOVED,
	STATE_CHANGED,
	CHECK_PERMISSIONS,
	ACTIVE_CONNECTION_ADDED,
	ACTIVE_CONNECTION_REMOVED,
	CONFIGURE_QUIT,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE (NMManager,
	PROP_VERSION,
	PROP_CAPABILITIES,
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
	PROP_GLOBAL_DNS_CONFIGURATION,
	PROP_ALL_DEVICES,

	/* Not exported */
	PROP_HOSTNAME,
	PROP_SLEEPING,
);

NM_DEFINE_SINGLETON_INSTANCE (NMManager);

/************************************************************************/

#define _NMLOG_PREFIX_NAME      "manager"
#define _NMLOG(level, domain, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        const NMLogDomain __domain = (domain); \
        \
        if (nm_logging_enabled (__level, __domain)) { \
            const NMManager *const __self = (self); \
            char __sbuf[32]; \
            \
            _nm_log (__level, __domain, 0, \
                     "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     _NMLOG_PREFIX_NAME, \
                     (__self && __self != singleton_instance) \
                         ? nm_sprintf_buf (__sbuf, "[%p]", __self) \
                         : "" \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/************************************************************************/

static void active_connection_state_changed (NMActiveConnection *active,
                                             GParamSpec *pspec,
                                             NMManager *self);
static void active_connection_default_changed (NMActiveConnection *active,
                                               GParamSpec *pspec,
                                               NMManager *self);
static void active_connection_parent_active (NMActiveConnection *active,
                                             NMActiveConnection *parent_ac,
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
		NMSettingsConnection *connection;

		priv->active_connections = g_slist_remove (priv->active_connections, active);
		g_signal_emit (self, signals[ACTIVE_CONNECTION_REMOVED], 0, active);
		g_signal_handlers_disconnect_by_func (active, active_connection_state_changed, self);
		g_signal_handlers_disconnect_by_func (active, active_connection_default_changed, self);
		g_signal_handlers_disconnect_by_func (active, active_connection_parent_active, self);

		if (   nm_active_connection_get_assumed (active)
		    && (connection = nm_active_connection_get_settings_connection (active))
		    && nm_settings_connection_get_nm_generated_assumed (connection))
			g_object_ref (connection);
		else
			connection = NULL;

		nm_exported_object_clear_and_unexport (&active);

		if (   connection
		    && nm_settings_has_connection (priv->settings, connection)) {
			_LOGD (LOGD_DEVICE, "assumed connection disconnected. Deleting generated connection '%s' (%s)",
			       nm_settings_connection_get_id (connection), nm_settings_connection_get_uuid (connection));
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
				_notify (self, PROP_ACTIVE_CONNECTIONS);
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
		_notify (self, PROP_ACTIVE_CONNECTIONS);
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
	const char *uuid = NULL;
	gboolean is_settings_connection;

	is_settings_connection = NM_IS_SETTINGS_CONNECTION (connection);

	if (!is_settings_connection)
		uuid = nm_connection_get_uuid (connection);

	for (iter = priv->active_connections; iter; iter = iter->next) {
		NMActiveConnection *ac = iter->data;
		NMSettingsConnection *con;

		con = nm_active_connection_get_settings_connection (ac);

		/* depending on whether we have a NMSettingsConnection or a NMConnection,
		 * we lookup by UUID or by reference. */
		if (is_settings_connection) {
			if (con != (NMSettingsConnection *) connection)
				continue;
		} else {
			if (strcmp (uuid, nm_connection_get_uuid (NM_CONNECTION (con))) != 0)
				continue;
		}
		if (nm_active_connection_get_state (ac) < NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
			return ac;
	}

	return NULL;
}

/* Filter out connections that are already active.
 * nm_settings_get_connections_sorted() returns sorted list. We need to preserve the
 * order so that we didn't change auto-activation order (recent timestamps
 * are first).
 * Caller is responsible for freeing the returned list with g_slist_free().
 */
GSList *
nm_manager_get_activatable_connections (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *all_connections = nm_settings_get_connections_sorted (priv->settings);
	GSList *connections = NULL, *iter;
	NMSettingsConnection *connection;

	for (iter = all_connections; iter; iter = iter->next) {
		connection = iter->data;

		if (!find_ac_for_connection (manager, NM_CONNECTION (connection)))
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

	if (NM_FLAGS_HAS (changes, NM_CONFIG_CHANGE_GLOBAL_DNS_CONFIG))
		_notify (self, PROP_GLOBAL_DNS_CONFIGURATION);
}

static void
_reload_auth_cb (NMAuthChain *chain,
                 GError *error,
                 GDBusMethodInvocation *context,
                 gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error = NULL;
	NMAuthCallResult result;
	guint32 flags;
	NMAuthSubject *subject;
	char s_buf[60];
	NMConfigChangeFlags reload_type = NM_CONFIG_CHANGE_NONE;

	g_assert (context);

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);
	flags = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "flags"));

	subject = nm_auth_chain_get_subject (chain);

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_RELOAD);
	if (error) {
		_LOGD (LOGD_CORE, "Reload request failed: %s", error->message);
		ret_error = g_error_new (NM_MANAGER_ERROR,
		                         NM_MANAGER_ERROR_PERMISSION_DENIED,
		                         "Reload request failed: %s",
		                         error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		ret_error = g_error_new_literal (NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
		                                 "Not authorized to reload configuration");
	} else {
		if (NM_FLAGS_ANY (flags, ~NM_MANAGER_RELOAD_FLAGS_ALL)) {
			/* invalid flags */
		} else if (flags == 0)
			reload_type = NM_CONFIG_CHANGE_CAUSE_SIGHUP;
		else {
			if (NM_FLAGS_HAS (flags, NM_MANAGER_RELOAD_FLAGS_CONF))
				reload_type |= NM_CONFIG_CHANGE_CAUSE_CONF;
			if (NM_FLAGS_HAS (flags, NM_MANAGER_RELOAD_FLAGS_DNS_RC))
				reload_type |= NM_CONFIG_CHANGE_CAUSE_DNS_RC;
			if (NM_FLAGS_HAS (flags, NM_MANAGER_RELOAD_FLAGS_DNS_FULL))
				reload_type |= NM_CONFIG_CHANGE_CAUSE_DNS_FULL;
		}

		if (reload_type == NM_CONFIG_CHANGE_NONE) {
			ret_error = g_error_new_literal (NM_MANAGER_ERROR,
			                                 NM_MANAGER_ERROR_INVALID_ARGUMENTS,
			                                 "Invalid flags for reload");
		}
	}

	nm_audit_log_control_op (NM_AUDIT_OP_RELOAD,
	                         nm_sprintf_buf (s_buf, "%u", flags),
	                         ret_error == NULL, subject,
	                         ret_error ? ret_error->message : NULL);

	if (ret_error) {
		g_dbus_method_invocation_take_error (context, ret_error);
		goto out;
	}

	nm_config_reload (priv->config, reload_type);
	g_dbus_method_invocation_return_value (context, NULL);

out:
	nm_auth_chain_unref (chain);
}

static void
impl_manager_reload (NMManager *self,
                     GDBusMethodInvocation *context,
                     guint32 flags)
{
	NMManagerPrivate *priv;
	NMAuthChain *chain;
	GError *error = NULL;

	g_return_if_fail (NM_IS_MANAGER (self));

	priv = NM_MANAGER_GET_PRIVATE (self);

	chain = nm_auth_chain_new_context (context, _reload_auth_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request");
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "flags", GUINT_TO_POINTER (flags), NULL);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_RELOAD, TRUE);
}

/************************************************************************/

NMDevice *
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
find_device_by_permanent_hw_addr (NMManager *manager, const char *hwaddr)
{
	GSList *iter;
	const char *device_addr;

	g_return_val_if_fail (hwaddr != NULL, NULL);

	if (nm_utils_hwaddr_valid (hwaddr, -1)) {
		for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
			device_addr = nm_device_get_permanent_hw_address (NM_DEVICE (iter->data), FALSE);
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
		NMDevice *candidate = iter->data;

		if (   nm_device_is_real (candidate)
		    && g_strcmp0 (nm_device_get_ip_iface (candidate), iface) == 0)
			return candidate;
	}
	return NULL;
}

/**
 * find_device_by_iface:
 * @self: the #NMManager
 * @iface: the device interface to find
 * @connection: a connection to ensure the returned device is compatible with
 * @slave: a slave connection to ensure a master is compatible with
 *
 * Finds a device by interface name, preferring realized devices.  If @slave
 * is given, this function will only return master devices and will ensure
 * @slave, when activated, can be a slave of the returned master device.  If
 * @connection is given, this function will only consider devices that are
 * compatible with @connection.
 *
 * Returns: the matching #NMDevice
 */
static NMDevice *
find_device_by_iface (NMManager *self,
                      const char *iface,
                      NMConnection *connection,
                      NMConnection *slave)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *fallback = NULL;
	GSList *iter;

	g_return_val_if_fail (iface != NULL, NULL);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;

		if (strcmp (nm_device_get_iface (candidate), iface))
			continue;
		if (connection && !nm_device_check_connection_compatible (candidate, connection))
			continue;
		if (slave) {
			if (!nm_device_is_master (candidate))
				continue;
			if (!nm_device_check_slave_connection_compatible (candidate, slave))
				continue;
		}

		if (nm_device_is_real (candidate))
			return candidate;
		else if (!fallback)
			fallback = candidate;
	}
	return fallback;
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
set_state (NMManager *self, NMState state)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->state == state)
		return;

	priv->state = state;

	_LOGI (LOGD_CORE, "NetworkManager state is now %s", _nm_state_to_string (state));

	_notify (self, PROP_STATE);
	g_signal_emit (self, signals[STATE_CHANGED], 0, priv->state);
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
		_notify (manager, PROP_CONNECTIVITY);
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
nm_manager_update_metered (NMManager *self)
{
	NMManagerPrivate *priv;
	NMDevice *device;
	NMMetered value = NM_METERED_UNKNOWN;

	g_return_if_fail (NM_IS_MANAGER (self));
	priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->primary_connection) {
		device =  nm_active_connection_get_device (priv->primary_connection);
		if (device)
			value = nm_device_get_metered (device);
	}

	if (value != priv->metered) {
		priv->metered = value;
		_LOGD (LOGD_CORE, "new metered value: %d", (int) priv->metered);
		_notify (self, PROP_METERED);
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
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_FAILED:
		_notify (self, PROP_ACTIVE_CONNECTIONS);
		break;
	default:
		break;
	}

	if (   new_state == NM_DEVICE_STATE_UNAVAILABLE
	    || new_state == NM_DEVICE_STATE_DISCONNECTED)
		nm_settings_device_added (priv->settings, device);
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

	if (!priv->devices_inited)
		return;

	if (!nm_settings_get_startup_complete (priv->settings)) {
		_LOGD (LOGD_CORE, "check_if_startup_complete returns FALSE because of NMSettings");
		return;
	}

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *dev = iter->data;

		if (nm_device_has_pending_action (dev)) {
			_LOGD (LOGD_CORE, "check_if_startup_complete returns FALSE because of %s",
			       nm_device_get_iface (dev));
			return;
		}
	}

	_LOGI (LOGD_CORE, "startup complete");

	priv->startup = FALSE;
	_notify (self, PROP_STARTUP);

	/* We don't have to watch notify::has-pending-action any more. */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *dev = iter->data;

		g_signal_handlers_disconnect_by_func (dev, G_CALLBACK (device_has_pending_action_changed), self);
	}

	if (nm_config_get_configure_and_quit (priv->config))
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
remove_device (NMManager *self,
               NMDevice *device,
               gboolean quitting,
               gboolean allow_unmanage)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean unmanage = FALSE;

	_LOGD (LOGD_DEVICE, "(%s): removing device (allow_unmanage %d, managed %d)",
	       nm_device_get_iface (device), allow_unmanage, nm_device_get_managed (device, FALSE));

	if (allow_unmanage && nm_device_get_managed (device, FALSE)) {

		if (quitting)
			unmanage = nm_device_unmanage_on_quit (device);
		else {
			/* the device is already gone. Unmanage it. */
			unmanage = TRUE;
		}

		if (unmanage) {
			if (quitting)
				nm_device_set_unmanaged_by_quitting (device);
			else
				nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_PLATFORM_INIT, TRUE, NM_DEVICE_STATE_REASON_REMOVED);
		} else if (quitting && nm_config_get_configure_and_quit (priv->config)) {
			nm_device_spawn_iface_helper (device);
		}
	}

	g_signal_handlers_disconnect_matched (device, G_SIGNAL_MATCH_DATA, 0, 0, NULL, NULL, self);

	nm_settings_device_removed (priv->settings, device, quitting);
	priv->devices = g_slist_remove (priv->devices, device);

	if (nm_device_is_real (device)) {
		gboolean unconfigure_ip_config = !quitting || unmanage;

		/* When we don't unmanage the device on shutdown, we want to preserve the DNS
		 * configuration in resolv.conf. For that, we must leak the configuration
		 * in NMPolicy/NMDnsManager. We do that, by emitting the device-removed signal
		 * with device's ip-config object still uncleared. In that case, NMPolicy
		 * never learns to unconfigure the ip-config objects and does not remove them
		 * from DNS on shutdown (which is ugly, because we don't cleanup the memory
		 * properly).
		 *
		 * Control that by passing @unconfigure_ip_config.  */
		nm_device_removed (device, unconfigure_ip_config);

		g_signal_emit (self, signals[DEVICE_REMOVED], 0, device);
		_notify (self, PROP_DEVICES);
	}
	g_signal_emit (self, signals[INTERNAL_DEVICE_REMOVED], 0, device);
	_notify (self, PROP_ALL_DEVICES);

	nm_exported_object_clear_and_unexport (&device);

	check_if_startup_complete (self);
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
find_parent_device_for_connection (NMManager *self, NMConnection *connection, NMDeviceFactory *cached_factory)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDeviceFactory *factory;
	const char *parent_name = NULL;
	NMSettingsConnection *parent_connection;
	NMDevice *parent, *first_compatible = NULL;
	GSList *iter;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	if (!cached_factory) {
		factory = nm_device_factory_manager_find_factory_for_connection (connection);
		if (!factory)
			return NULL;
	} else
		factory = cached_factory;

	parent_name = nm_device_factory_get_connection_parent (factory, connection);
	if (!parent_name)
		return NULL;

	/* Try as an interface name of a parent device */
	parent = find_device_by_iface (self, parent_name, NULL, NULL);
	if (parent)
		return parent;

	/* Maybe a hardware address */
	parent = find_device_by_permanent_hw_addr (self, parent_name);
	if (parent)
		return parent;

	/* Maybe a connection UUID */
	parent_connection = nm_settings_get_connection_by_uuid (priv->settings, parent_name);
	if (!parent_connection)
		return NULL;

	/* Check if the parent connection is currently activated or is comaptible
	 * with some known device.
	 */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;

		if (nm_device_get_settings_connection (candidate) == parent_connection)
			return candidate;

		if (   !first_compatible
		    && nm_device_check_connection_compatible (candidate, NM_CONNECTION (parent_connection)))
			first_compatible = candidate;
	}

	return first_compatible;
}

/**
 * nm_manager_get_connection_iface:
 * @self: the #NMManager
 * @connection: the #NMConnection to get the interface for
 * @out_parent: on success, the parent device if any
 * @error: an error if determining the virtual interface name failed
 *
 * Given @connection, returns the interface name that the connection
 * would need to use when activated. %NULL is returned if the name
 * is not specified in connection or a the name for a virtual device
 * could not be generated.
 *
 * Returns: the expected interface name (caller takes ownership), or %NULL
 */
char *
nm_manager_get_connection_iface (NMManager *self,
                                 NMConnection *connection,
                                 NMDevice **out_parent,
                                 GError **error)
{
	NMDeviceFactory *factory;
	char *iface = NULL;
	NMDevice *parent = NULL;

	if (out_parent)
		*out_parent = NULL;

	factory = nm_device_factory_manager_find_factory_for_connection (connection);
	if (!factory) {
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_FAILED,
		             "NetworkManager plugin for '%s' unavailable",
		             nm_connection_get_connection_type (connection));
		return NULL;
	}

	if (   !out_parent
	    && !NM_DEVICE_FACTORY_GET_INTERFACE (factory)->get_connection_iface) {
		/* optimization. Shortcut lookup of the partent device. */
		iface = g_strdup (nm_connection_get_interface_name (connection));
		if (!iface) {
			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_FAILED,
			             "failed to determine interface name: error determine name for %s",
			             nm_connection_get_connection_type (connection));
		}
		return iface;
	}

	parent = find_parent_device_for_connection (self, connection, factory);
	iface = nm_device_factory_get_connection_iface (factory,
	                                                connection,
	                                                parent ? nm_device_get_ip_iface (parent) : NULL,
	                                                error);
	if (!iface)
		return NULL;

	if (out_parent)
		*out_parent = parent;
	return iface;
}

/**
 * system_create_virtual_device:
 * @self: the #NMManager
 * @connection: the connection which might require a virtual device
 *
 * If @connection requires a virtual device and one does not yet exist for it,
 * creates that device.
 *
 * Returns: A #NMDevice that was just realized; %NULL if none
 */
static NMDevice *
system_create_virtual_device (NMManager *self, NMConnection *connection)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDeviceFactory *factory;
	gs_free_slist GSList *connections = NULL;
	GSList *iter;
	gs_free char *iface = NULL;
	NMDevice *device = NULL, *parent = NULL;
	GError *error = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (self), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	iface = nm_manager_get_connection_iface (self, connection, &parent, &error);
	if (!iface) {
		_LOGD (LOGD_DEVICE, "(%s) can't get a name of a virtual device: %s",
		       nm_connection_get_id (connection), error->message);
		g_error_free (error);
		return NULL;
	}

	/* See if there's a device that is already compatible with this connection */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = iter->data;

		if (nm_device_check_connection_compatible (candidate, connection)) {
			if (nm_device_is_real (candidate)) {
				_LOGD (LOGD_DEVICE, "(%s) already created virtual interface name %s",
				       nm_connection_get_id (connection), iface);
				return NULL;
			}

			device = candidate;
			break;
		}
	}

	if (!device) {
		/* No matching device found. Proceed creating a new one. */

		factory = nm_device_factory_manager_find_factory_for_connection (connection);
		if (!factory) {
			_LOGE (LOGD_DEVICE, "(%s:%s) NetworkManager plugin for '%s' unavailable",
			       nm_connection_get_id (connection), iface,
			       nm_connection_get_connection_type (connection));
			return NULL;
		}

		device = nm_device_factory_create_device (factory, iface, NULL, connection, NULL, &error);
		if (!device) {
			_LOGW (LOGD_DEVICE, "(%s) factory can't create the device: %s",
			       nm_connection_get_id (connection), error->message);
			g_error_free (error);
			return NULL;
		}

		_LOGD (LOGD_DEVICE, "(%s) create virtual device %s",
		       nm_connection_get_id (connection),
		       nm_device_get_iface (device));

		if (!add_device (self, device, &error)) {
			_LOGW (LOGD_DEVICE, "(%s) can't register the device with manager: %s",
			       nm_connection_get_id (connection), error->message);
			g_error_free (error);
			g_object_unref (device);
			return NULL;
		}

		/* Add device takes a reference that NMManager still owns, so it's
		 * safe to unref here and still return @device.
		 */
		g_object_unref (device);
	}

	/* Create backing resources if the device has any autoconnect connections */
	connections = nm_settings_get_connections_sorted (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = iter->data;
		NMSettingConnection *s_con;

		if (!nm_device_check_connection_compatible (device, candidate))
			continue;

		s_con = nm_connection_get_setting_connection (candidate);
		g_assert (s_con);
		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		/* Create any backing resources the device needs */
		if (!nm_device_create_and_realize (device, connection, parent, &error)) {
			_LOGW (LOGD_DEVICE, "(%s) couldn't create the device: %s",
			       nm_connection_get_id (connection), error->message);
			g_error_free (error);
			remove_device (self, device, FALSE, TRUE);
			return NULL;
		}
		break;
	}

	return device;
}

static void
retry_connections_for_parent_device (NMManager *self, NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *connections, *iter;

	g_return_if_fail (device);

	connections = nm_settings_get_connections_sorted (priv->settings);
	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = iter->data;
		gs_free_error GError *error = NULL;
		gs_free char *ifname = NULL;
		NMDevice *parent;

		parent = find_parent_device_for_connection (self, candidate, NULL);
		if (parent == device) {
			/* Only try to activate devices that don't already exist */
			ifname = nm_manager_get_connection_iface (self, candidate, &parent, &error);
			if (ifname) {
				if (!nm_platform_link_get_by_ifname (NM_PLATFORM_GET, ifname))
					connection_changed (self, candidate);
			}
		}
	}

	g_slist_free (connections);
}

static void
connection_changed (NMManager *self,
                    NMConnection *connection)
{
	NMDevice *device;

	if (!nm_connection_is_virtual (connection))
		return;

	device = system_create_virtual_device (self, connection);
	if (!device)
		return;

	/* Maybe the device that was created was needed by some other
	 * connection's device (parent of a VLAN). Let the connections
	 * can use the newly created device as a parent know. */
	retry_connections_for_parent_device (self, device);
}

static void
connection_added_cb (NMSettings *settings,
                     NMConnection *connection,
                     NMManager *self)
{
	connection_changed (self, connection);
}

static void
connection_updated_cb (NMSettings *settings,
                       NMConnection *connection,
                       gboolean by_user,
                       NMManager *self)
{
	if (by_user)
		connection_changed (self, connection);
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
	for (iter = priv->devices; iter; iter = g_slist_next (iter))
		nm_device_set_unmanaged_by_user_settings (NM_DEVICE (iter->data), unmanaged_specs);
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

	/* nm_settings_get_hostname() does not return an empty hostname. */
	nm_assert (!hostname || *hostname);

	if (!hostname && !priv->hostname)
		return;
	if (hostname && priv->hostname && !strcmp (hostname, priv->hostname)) {
		g_free (hostname);
		return;
	}

	/* realloc, to free possibly trailing data after NUL. */
	if (hostname)
		hostname = g_realloc (hostname, strlen (hostname) + 1);

	g_free (priv->hostname);
	priv->hostname = hostname;
	_notify (self, PROP_HOSTNAME);

	nm_dhcp_manager_set_default_hostname (nm_dhcp_manager_get (), priv->hostname);
}

/*******************************************************************/
/* General NMManager stuff                                         */
/*******************************************************************/

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
			_LOGD (LOGD_RFKILL, "(%s): setting radio %s",
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
		_LOGD (LOGD_RFKILL, "%s hw-enabled %d sw-enabled %d",
		       rstate->desc, rstate->hw_enabled, rstate->sw_enabled);
	}

	/* Log new killswitch state */
	new_rfkilled = rstate->hw_enabled && rstate->sw_enabled;
	if (old_rfkilled != new_rfkilled) {
		_LOGI (LOGD_RFKILL, "%s now %s by radio killswitch",
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
                     GDBusMethodInvocation *context,
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
		_LOGD (LOGD_CORE, "%s request failed: %s", permission, auth_error->message);
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "%s request failed: %s",
		                     permission, auth_error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		_LOGD (LOGD_CORE, "%s request failed: not authorized", permission);
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
                        GDBusMethodInvocation *context,
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
static NMSettingsConnection *
get_existing_connection (NMManager *self, NMDevice *device, gboolean *out_generated)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gs_free_slist GSList *connections = nm_manager_get_activatable_connections (self);
	NMConnection *connection = NULL;
	NMSettingsConnection *matched;
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
			master = nm_manager_get_device_by_ifindex (self, master_ifindex);
			if (!master) {
				_LOGD (LOGD_DEVICE, "(%s): cannot generate connection for slave before its master (%s/%d)",
				       nm_device_get_iface (device), nm_platform_link_get_name (NM_PLATFORM_GET, master_ifindex), master_ifindex);
				return NULL;
			}
			if (!nm_device_get_act_request (master)) {
				_LOGD (LOGD_DEVICE, "(%s): cannot generate connection for slave before master %s activates",
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
	matched = NM_SETTINGS_CONNECTION (nm_utils_match_connection (connections,
	                                                             connection,
	                                                             nm_device_has_carrier (device),
	                                                             nm_device_get_ip4_route_metric (device),
	                                                             nm_device_get_ip6_route_metric (device),
	                                                             match_connection_filter,
	                                                             device));
	if (matched) {
		_LOGI (LOGD_DEVICE, "(%s): found matching connection '%s'",
		       nm_device_get_iface (device),
		       nm_settings_connection_get_id (matched));
		g_object_unref (connection);
		return matched;
	}

	_LOGD (LOGD_DEVICE, "(%s): generated connection '%s'",
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
		_LOGW (LOGD_SETTINGS, "(%s) Couldn't save generated connection '%s': %s",
		       nm_device_get_iface (device),
		       nm_connection_get_id (connection),
		       error->message);
		g_clear_error (&error);
	}
	g_object_unref (connection);

	return added ? added : NULL;
}

static gboolean
assume_connection (NMManager *self, NMDevice *device, NMSettingsConnection *connection)
{
	NMActiveConnection *active, *master_ac;
	NMAuthSubject *subject;
	GError *error = NULL;

	_LOGD (LOGD_DEVICE, "(%s): will attempt to assume connection",
	       nm_device_get_iface (device));

	/* Move device to DISCONNECTED to activate the connection */
	if (nm_device_get_state (device) == NM_DEVICE_STATE_UNAVAILABLE) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_CONNECTION_ASSUMED);
	}
	g_return_val_if_fail (nm_device_get_state (device) >= NM_DEVICE_STATE_DISCONNECTED, FALSE);

	subject = nm_auth_subject_new_internal ();
	active = _new_active_connection (self, NM_CONNECTION (connection), NULL, device, subject, &error);
	g_object_unref (subject);

	if (!active) {
		_LOGW (LOGD_DEVICE, "assumed connection %s failed to activate: %s",
		       nm_connection_get_path (NM_CONNECTION (connection)),
		       error->message);
		g_error_free (error);
		return FALSE;
	}

	/* If the device is a slave or VLAN, find the master ActiveConnection */
	master_ac = NULL;
	if (find_master (self, NM_CONNECTION (connection), device, NULL, NULL, &master_ac, NULL) && master_ac)
		nm_active_connection_set_master (active, master_ac);

	nm_active_connection_set_assumed (active, TRUE);
	nm_exported_object_export (NM_EXPORTED_OBJECT (active));
	active_connection_add (self, active);
	nm_device_queue_activation (device, NM_ACT_REQUEST (active));
	g_object_unref (active);

	return TRUE;
}

static gboolean
recheck_assume_connection (NMManager *self, NMDevice *device)
{
	NMSettingsConnection *connection;
	gboolean was_unmanaged = FALSE, success, generated = FALSE;
	NMDeviceState state;

	g_return_val_if_fail (NM_IS_MANAGER (self), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	if (nm_device_get_is_nm_owned (device))
		return FALSE;

	if (!nm_device_get_managed (device, FALSE))
		return FALSE;

	state = nm_device_get_state (device);
	if (state > NM_DEVICE_STATE_DISCONNECTED)
		return FALSE;

	connection = get_existing_connection (self, device, &generated);
	if (!connection) {
		_LOGD (LOGD_DEVICE, "(%s): can't assume; no connection",
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
		}

		if (generated) {
			_LOGD (LOGD_DEVICE, "(%s): connection assumption failed. Deleting generated connection",
			       nm_device_get_iface (device));

			nm_settings_connection_delete (connection, NULL, NULL);
		}
	}

	return success;
}

static void
recheck_assume_connection_cb (NMDevice *device, gpointer user_data)
{
	recheck_assume_connection (user_data, device);
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
		    && g_strcmp0 (nm_device_get_iface (candidate), ip_iface) == 0
		    && nm_device_is_real (candidate)) {
			remove_device (self, candidate, FALSE, FALSE);
			break;
		}
	}
}

static void
device_iface_changed (NMDevice *device,
                      GParamSpec *pspec,
                      NMManager *self)
{
	/* Virtual connections may refer to the new device name as
	 * parent device, retry to activate them.
	 */
	retry_connections_for_parent_device (self, device);
}


static void
device_realized (NMDevice *device,
                 GParamSpec *pspec,
                 NMManager *self)
{
	gboolean real = nm_device_is_real (device);

	/* Emit D-Bus signals */
	g_signal_emit (self, signals[real ? DEVICE_ADDED : DEVICE_REMOVED], 0, device);
	_notify (self, PROP_DEVICES);
}

static void
_device_realize_finish (NMManager *self, NMDevice *device, const NMPlatformLink *plink)
{
	g_return_if_fail (NM_IS_MANAGER (self));
	g_return_if_fail (NM_IS_DEVICE (device));

	nm_device_realize_finish (device, plink);

	if (!nm_device_get_managed (device, FALSE))
		return;

	if (recheck_assume_connection (self, device))
		return;

	/* if we failed to assume a connection for the managed device, but the device
	 * is still unavailable. Set UNAVAILABLE state again, this time with NOW_MANAGED. */
	nm_device_state_changed (device,
	                         NM_DEVICE_STATE_UNAVAILABLE,
	                         NM_DEVICE_STATE_REASON_NOW_MANAGED);
	nm_device_emit_recheck_auto_activate (device);
}

/**
 * add_device:
 * @self: the #NMManager
 * @device: the #NMDevice to add
 * @error: (out): the #GError
 *
 * If successful, this function will increase the references count of @device.
 * Callers should decrease the reference count.
 */
static gboolean
add_device (NMManager *self, NMDevice *device, GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	const char *iface, *type_desc;
	RfKillType rtype;
	GSList *iter, *remove = NULL;
	int ifindex;
	const char *dbus_path;

	/* No duplicates */
	ifindex = nm_device_get_ifindex (device);
	if (ifindex > 0 && nm_manager_get_device_by_ifindex (self, ifindex)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		             "A device with ifindex %d already exists", ifindex);
		return FALSE;
	}

	/* Remove existing devices owned by the new device; eg remove ethernet
	 * ports that are owned by a WWAN modem, since udev may announce them
	 * before the modem is fully discovered.
	 *
	 * FIXME: use parent/child device relationships instead of removing
	 * the child NMDevice entirely
	 */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;

		iface = nm_device_get_ip_iface (candidate);
		if (nm_device_is_real (candidate) && nm_device_owns_iface (device, iface))
			remove = g_slist_prepend (remove, candidate);
	}
	for (iter = remove; iter; iter = iter->next)
		remove_device (self, NM_DEVICE (iter->data), FALSE, FALSE);
	g_slist_free (remove);

	priv->devices = g_slist_append (priv->devices, g_object_ref (device));

	g_signal_connect (device, NM_DEVICE_STATE_CHANGED,
	                  G_CALLBACK (manager_device_state_changed),
	                  self);

	g_signal_connect (device, NM_DEVICE_AUTH_REQUEST,
	                  G_CALLBACK (device_auth_request_cb),
	                  self);

	g_signal_connect (device, NM_DEVICE_REMOVED,
	                  G_CALLBACK (device_removed_cb),
	                  self);

	g_signal_connect (device, NM_DEVICE_RECHECK_ASSUME,
	                  G_CALLBACK (recheck_assume_connection_cb),
	                  self);

	g_signal_connect (device, "notify::" NM_DEVICE_IP_IFACE,
	                  G_CALLBACK (device_ip_iface_changed),
	                  self);

	g_signal_connect (device, "notify::" NM_DEVICE_IFACE,
	                  G_CALLBACK (device_iface_changed),
	                  self);

	g_signal_connect (device, "notify::" NM_DEVICE_REAL,
	                  G_CALLBACK (device_realized),
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
		nm_device_set_enabled (device, radio_enabled_for_type (self, rtype, TRUE));
	}

	iface = nm_device_get_iface (device);
	g_assert (iface);
	type_desc = nm_device_get_type_desc (device);
	g_assert (type_desc);

	nm_device_set_unmanaged_by_user_settings (device, nm_settings_get_unmanaged_specs (priv->settings));

	nm_device_set_unmanaged_flags (device,
	                               NM_UNMANAGED_SLEEPING,
	                               manager_sleeping (self));

	dbus_path = nm_exported_object_export (NM_EXPORTED_OBJECT (device));
	_LOGI (LOGD_DEVICE, "(%s): new %s device (%s)", iface, type_desc, dbus_path);

	nm_settings_device_added (priv->settings, device);
	g_signal_emit (self, signals[INTERNAL_DEVICE_ADDED], 0, device);
	_notify (self, PROP_ALL_DEVICES);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *d = iter->data;

		if (d != device)
			nm_device_notify_new_device_added (d, device);
	}

	/* Virtual connections may refer to the new device as
	 * parent device, retry to activate them.
	 */
	retry_connections_for_parent_device (self, device);

	return TRUE;
}

/*******************************************************************/

static void
factory_device_added_cb (NMDeviceFactory *factory,
                         NMDevice *device,
                         gpointer user_data)
{
	NMManager *self = user_data;
	GError *error = NULL;

	g_return_if_fail (NM_IS_MANAGER (self));

	if (nm_device_realize_start (device, NULL, NULL, &error)) {
		add_device (self, device, NULL);
		_device_realize_finish (self, device, NULL);
	} else {
		_LOGW (LOGD_DEVICE, "(%s): failed to realize device: %s",
		       nm_device_get_iface (device), error->message);
		g_error_free (error);
	}
}

static gboolean
factory_component_added_cb (NMDeviceFactory *factory,
                            GObject *component,
                            gpointer user_data)
{
	NMManager *self = user_data;
	GSList *iter;

	g_return_val_if_fail (self, FALSE);

	for (iter = NM_MANAGER_GET_PRIVATE (self)->devices; iter; iter = iter->next) {
		if (nm_device_notify_component_added ((NMDevice *) iter->data, component))
			return TRUE;
	}
	return FALSE;
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
                     const NMPlatformLink *plink)
{
	NMDeviceFactory *factory;
	NMDevice *device = NULL;
	gboolean nm_plugin_missing = FALSE;
	GSList *iter;

	g_return_if_fail (ifindex > 0);

	if (nm_manager_get_device_by_ifindex (self, ifindex))
		return;

	/* Let unrealized devices try to realize themselves with the link */
	for (iter = NM_MANAGER_GET_PRIVATE (self)->devices; iter; iter = iter->next) {
		NMDevice *candidate = iter->data;
		gboolean compatible = TRUE;
		gs_free_error GError *error = NULL;

		if (strcmp (nm_device_get_iface (candidate), plink->name))
			continue;

		if (nm_device_is_real (candidate)) {
			/* Ignore the link added event since there's already a realized
			 * device with the link's name.
			 */
			return;
		} else if (nm_device_realize_start (candidate, plink, &compatible, &error)) {
			/* Success */
			_device_realize_finish (self, candidate, plink);
			return;
		}

		_LOGD (LOGD_DEVICE, "(%s): failed to realize from plink: '%s'",
		       plink->name, error->message);

		/* Try next unrealized device */
	}

	/* Try registered device factories */
	factory = nm_device_factory_manager_find_factory_for_link_type (plink->type);
	if (factory) {
		gboolean ignore = FALSE;
		gs_free_error GError *error = NULL;

		device = nm_device_factory_create_device (factory, plink->name, plink, NULL, &ignore, &error);
		if (!device) {
			if (!ignore) {
				_LOGW (LOGD_HW, "%s: factory failed to create device: %s",
				       plink->name, error->message);
			} else {
				_LOGD (LOGD_HW, "%s: factory failed to create device: %s",
				       plink->name, error->message);
			}
			return;
		}
	}

	if (device == NULL) {
		switch (plink->type) {
		case NM_LINK_TYPE_WWAN_NET:
		case NM_LINK_TYPE_BNEP:
		case NM_LINK_TYPE_OLPC_MESH:
		case NM_LINK_TYPE_TEAM:
		case NM_LINK_TYPE_WIFI:
			_LOGI (LOGD_HW, "(%s): '%s' plugin not available; creating generic device",
			       plink->name, nm_link_type_to_string (plink->type));
			nm_plugin_missing = TRUE;
			/* fall through */
		default:
			device = nm_device_generic_new (plink);
			break;
		}
	}

	if (device) {
		gs_free_error GError *error = NULL;

		if (nm_plugin_missing)
			nm_device_set_nm_plugin_missing (device, TRUE);
		if (nm_device_realize_start (device, plink, NULL, &error)) {
			add_device (self, device, NULL);
			_device_realize_finish (self, device, plink);
		} else {
			_LOGW (LOGD_DEVICE, "%s: failed to realize device: %s",
			       plink->name, error->message);
		}
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
	const NMPlatformLink *l;

	if (!self)
		goto out;

	g_object_remove_weak_pointer (G_OBJECT (self), (gpointer *) &data->self);

	l = nm_platform_link_get (NM_PLATFORM_GET, data->ifindex);
	if (l) {
		NMPlatformLink pllink;

		pllink = *l; /* make a copy of the link instance */
		platform_link_added (self, data->ifindex, &pllink);
	} else {
		NMDevice *device;
		GError *error = NULL;

		device = nm_manager_get_device_by_ifindex (self, data->ifindex);
		if (device) {
			if (nm_device_is_software (device)) {
				/* Our software devices stick around until their connection is removed */
				if (!nm_device_unrealize (device, FALSE, &error)) {
					_LOGW (LOGD_DEVICE, "(%s): failed to unrealize: %s",
					       nm_device_get_iface (device),
					       error->message);
					g_clear_error (&error);
					remove_device (self, device, FALSE, TRUE);
				}
			} else {
				/* Hardware and external devices always get removed when their kernel link is gone */
				remove_device (self, device, FALSE, TRUE);
			}
		}
	}

out:
	g_slice_free (PlatformLinkCbData, data);
	return G_SOURCE_REMOVE;
}

static void
platform_link_cb (NMPlatform *platform,
                  NMPObjectType obj_type,
                  int ifindex,
                  NMPlatformLink *plink,
                  NMPlatformSignalChangeType change_type,
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
                                           NMConnection *connection,
                                           gboolean for_user_request)
{
	const GSList *devices, *iter;
	NMDevice *act_device = nm_manager_get_connection_device (self, connection);
	NMDeviceCheckConAvailableFlags flags;

	if (act_device)
		return act_device;

	flags = for_user_request ? NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST : NM_DEVICE_CHECK_CON_AVAILABLE_NONE;

	/* Pick the first device that's compatible with the connection. */
	devices = nm_manager_get_devices (self);
	for (iter = devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_check_connection_available (device, connection, flags, NULL))
			return device;
	}

	/* No luck. :( */
	return NULL;
}

static void
_get_devices (NMManager *self,
              GDBusMethodInvocation *context,
              gboolean all_devices)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gs_free const char **paths = NULL;
	guint i;
	GSList *iter;

	paths = g_new (const char *, g_slist_length (priv->devices) + 1);

	for (i = 0, iter = priv->devices; iter; iter = iter->next) {
		const char *path;

		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (iter->data));
		if (   path
		    && (all_devices || nm_device_is_real (iter->data)))
			paths[i++] = path;
	}
	paths[i++] = NULL;

	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(^ao)", (char **) paths));
}

static void
impl_manager_get_devices (NMManager *self,
                          GDBusMethodInvocation *context)
{
	_get_devices (self, context, FALSE);
}

static void
impl_manager_get_all_devices (NMManager *self,
                              GDBusMethodInvocation *context)
{
	_get_devices (self, context, TRUE);
}

static void
impl_manager_get_device_by_ip_iface (NMManager *self,
                                     GDBusMethodInvocation *context,
                                     const char *iface)
{
	NMDevice *device;
	const char *path = NULL;

	device = find_device_by_ip_iface (self, iface);
	if (device)
		path = nm_exported_object_get_path (NM_EXPORTED_OBJECT (device));

	if (path == NULL) {
		g_dbus_method_invocation_return_error (context,
		                                       NM_MANAGER_ERROR,
		                                       NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		                                       "No device found for the requested iface.");
	} else {
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(o)", path));
	}
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
             NMSettingsConnection **out_master_connection,
             NMDevice **out_master_device,
             NMActiveConnection **out_master_ac,
             GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *master;
	NMDevice *master_device = NULL;
	NMSettingsConnection *master_connection = NULL;
	GSList *iter;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	master = nm_setting_connection_get_master (s_con);

	if (master == NULL)
		return TRUE;  /* success, but no master */

	/* Try as an interface name first */
	master_device = find_device_by_iface (self, master, NULL, connection);
	if (master_device) {
		if (master_device == device) {
			g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			                     "Device cannot be its own master");
			return FALSE;
		}

		master_connection = nm_device_get_settings_connection (master_device);
		if (master_connection && !is_compatible_with_slave (NM_CONNECTION (master_connection), connection)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			             "The active connection on %s is not compatible",
			             nm_device_get_iface (master_device));
			return FALSE;
		}
	} else {
		/* Try master as a connection UUID */
		master_connection = nm_settings_get_connection_by_uuid (priv->settings, master);
		if (master_connection) {
			/* Check if the master connection is activated on some device already */
			for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
				NMDevice *candidate = NM_DEVICE (iter->data);

				if (candidate == device)
					continue;

				if (nm_device_get_settings_connection (candidate) == master_connection) {
					master_device = candidate;
					break;
				}
			}
		}
	}

	if (out_master_connection)
		*out_master_connection = master_connection;
	if (out_master_device)
		*out_master_device = master_device;
	if (out_master_ac && master_connection)
		*out_master_ac = find_ac_for_connection (self, NM_CONNECTION (master_connection));

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
                                 NMSettingsConnection *master_connection,
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
		NMSettingsConnection *device_connection = nm_device_get_settings_connection (master_device);

		/* If we're passed a connection and a device, we require that connection
		 * be already activated on the device, eg returned from find_master().
		 */
		g_assert (!master_connection || master_connection == device_connection);
		if (device_connection && !is_compatible_with_slave (NM_CONNECTION (device_connection), connection)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			             "The active connection %s is not compatible",
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
		if (master_state == NM_DEVICE_STATE_DISCONNECTED || !nm_device_is_real (master_device)) {
			GSList *connections;

			g_assert (master_connection == NULL);

			/* Find a compatible connection and activate this device using it */
			connections = nm_manager_get_activatable_connections (self);
			for (iter = connections; iter; iter = g_slist_next (iter)) {
				NMSettingsConnection *candidate = NM_SETTINGS_CONNECTION (iter->data);

				/* Ensure eg bond/team slave and the candidate master is a
				 * bond/team master
				 */
				if (!is_compatible_with_slave (NM_CONNECTION (candidate), connection))
					continue;

				if (nm_device_check_connection_available (master_device, NM_CONNECTION (candidate), NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL)) {
					master_ac = nm_manager_activate_connection (self,
					                                            candidate,
					                                            NULL,
					                                            master_device,
					                                            subject,
					                                            error);
					g_slist_free (connections);
					return master_ac;
				}
			}
			g_slist_free (connections);

			g_set_error (error,
			             NM_MANAGER_ERROR,
			             NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
			             "No compatible connection found.");
			return NULL;
		}

		/* Otherwise, the device is unmanaged, unavailable, or disconnecting */
		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_DEPENDENCY_FAILED,
		             "Device unmanaged or not available for activation");
	} else if (master_connection) {
		gboolean found_device = FALSE;

		/* Find a compatible device and activate it using this connection */
		for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
			NMDevice *candidate = NM_DEVICE (iter->data);

			if (candidate == device) {
				/* A device obviously can't be its own master */
				continue;
			}

			if (!nm_device_check_connection_available (candidate, NM_CONNECTION (master_connection), NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL))
				continue;

			found_device = TRUE;
			if (!nm_device_is_software (candidate)) {
				master_state = nm_device_get_state (candidate);
				if (nm_device_is_real (candidate) && master_state != NM_DEVICE_STATE_DISCONNECTED)
					continue;
			}

			master_ac = nm_manager_activate_connection (self,
			                                            master_connection,
			                                            NULL,
			                                            candidate,
			                                            subject,
			                                            error);
			return master_ac;
		}

		g_set_error (error,
		             NM_MANAGER_ERROR,
		             NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		             "No device available");
	} else
		g_assert_not_reached ();

	return NULL;
}

/**
 * find_slaves:
 * @manager: #NMManager object
 * @connection: the master #NMSettingsConnection to find slave connections for
 * @device: the master #NMDevice for the @connection
 *
 * Given an #NMSettingsConnection, attempts to find its slaves. If @connection is not
 * master, or has not any slaves, this will return %NULL.
 *
 * Returns: list of slave connections for given master @connection, or %NULL
 **/
static GSList *
find_slaves (NMManager *manager,
             NMSettingsConnection *connection,
             NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *all_connections, *iter;
	GSList *slaves = NULL;
	NMSettingConnection *s_con;
	const char *master;

	s_con = nm_connection_get_setting_connection (NM_CONNECTION (connection));
	g_assert (s_con);
	master = nm_setting_connection_get_master (s_con);

	if (master != NULL)
		return NULL;  /* connection is not master */

	/* Search through all connections, not only inactive ones, because
	 * even if a slave was already active, it might be deactivated during
	 * master reactivation.
	 */
	all_connections = nm_settings_get_connections_sorted (priv->settings);
	for (iter = all_connections; iter; iter = iter->next) {
		NMSettingsConnection *master_connection = NULL;
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
autoconnect_slaves (NMManager *self,
                    NMSettingsConnection *master_connection,
                    NMDevice *master_device,
                    NMAuthSubject *subject)
{
	GError *local_err = NULL;
	gboolean ret = FALSE;

	if (should_connect_slaves (NM_CONNECTION (master_connection), master_device)) {
		GSList *slaves, *iter;

		iter = slaves = find_slaves (self, master_connection, master_device);
		ret = slaves != NULL;

		while (iter) {
			NMSettingsConnection *slave_connection = iter->data;

			iter = iter->next;
			_LOGD (LOGD_CORE, "will activate slave connection '%s' (%s) as a dependency for master '%s' (%s)",
			       nm_settings_connection_get_id (slave_connection),
			       nm_settings_connection_get_uuid (slave_connection),
			       nm_settings_connection_get_id (master_connection),
			       nm_settings_connection_get_uuid (master_connection));

			/* Schedule slave activation */
			nm_manager_activate_connection (self,
			                                slave_connection,
			                                NULL,
			                                nm_manager_get_best_device_for_connection (self, NM_CONNECTION (slave_connection), FALSE),
			                                subject,
			                                &local_err);
			if (local_err) {
				_LOGW (LOGD_CORE, "Slave connection activation failed: %s", local_err->message);
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
	g_assert (NM_IS_VPN_CONNECTION (active));

	nm_exported_object_export (NM_EXPORTED_OBJECT (active));
	return nm_vpn_manager_activate_connection (NM_MANAGER_GET_PRIVATE (self)->vpn_manager,
	                                           NM_VPN_CONNECTION (active),
	                                           error);
}

/* Traverse the device to disconnected state. This means that the device is ready
 * for connection and will proceed activating if there's an activation request
 * enqueued.
 */
static void
unmanaged_to_disconnected (NMDevice *device)
{
	/* when creating the software device, it can happen that the device is
	 * still unmanaged by NM_UNMANAGED_PLATFORM_INIT because we didn't yet
	 * get the udev event. At this point, we can no longer delay the activation
	 * and force the device to be managed. */
	nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_PLATFORM_INIT, FALSE, NM_DEVICE_STATE_REASON_USER_REQUESTED);

	nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_USER_EXPLICIT, FALSE, NM_DEVICE_STATE_REASON_USER_REQUESTED);

	g_return_if_fail (nm_device_get_managed (device, FALSE));

	if (nm_device_get_state (device) == NM_DEVICE_STATE_UNMANAGED) {
		nm_device_state_changed (device,
					 NM_DEVICE_STATE_UNAVAILABLE,
					 NM_DEVICE_STATE_REASON_USER_REQUESTED);
	}

	if (   nm_device_is_available (device, NM_DEVICE_CHECK_DEV_AVAILABLE_FOR_USER_REQUEST)
	    && (nm_device_get_state (device) == NM_DEVICE_STATE_UNAVAILABLE)) {
		nm_device_state_changed (device,
					 NM_DEVICE_STATE_DISCONNECTED,
					 NM_DEVICE_STATE_REASON_USER_REQUESTED);
	}
}

/* The parent connection is ready; we can proceed realizing the device and
 * progressing the device to disconencted state.
 */
static void
active_connection_parent_active (NMActiveConnection *active,
                                 NMActiveConnection *parent_ac,
                                 NMManager *self)
{
	NMDevice *device = nm_active_connection_get_device (active);
	GError *error = NULL;

	g_signal_handlers_disconnect_by_func (active,
	                                      (GCallback) active_connection_parent_active,
	                                      self);

	if (parent_ac) {
		NMSettingsConnection *connection = nm_active_connection_get_settings_connection (active);
		NMDevice *parent = nm_active_connection_get_device (parent_ac);

		if (nm_device_create_and_realize (device, (NMConnection *) connection, parent, &error)) {
			/* We can now proceed to disconnected state so that activation proceeds. */
			unmanaged_to_disconnected (device);
		} else {
			_LOGW (LOGD_CORE, "Could not realize device '%s': %s",
			       nm_device_get_iface (device), error->message);
			nm_active_connection_set_state (active, NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);
		}
	} else {
		_LOGW (LOGD_CORE, "The parent connection device '%s' depended on disappeared.",
		       nm_device_get_iface (device));
		nm_active_connection_set_state (active, NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);
	}
}

static gboolean
_internal_activate_device (NMManager *self, NMActiveConnection *active, GError **error)
{
	NMDevice *device, *existing, *master_device = NULL;
	NMConnection *applied;
	NMSettingsConnection *connection;
	NMSettingsConnection *master_connection = NULL;
	NMConnection *existing_connection = NULL;
	NMActiveConnection *master_ac = NULL;
	NMAuthSubject *subject;
	char *error_desc = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (self), FALSE);
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (active), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	g_assert (NM_IS_VPN_CONNECTION (active) == FALSE);

	connection = nm_active_connection_get_settings_connection (active);
	g_assert (connection);

	applied = nm_active_connection_get_applied_connection (active);

	device = nm_active_connection_get_device (active);
	g_return_val_if_fail (device != NULL, FALSE);

	/* If the device is active and its connection is not visible to the
	 * user that's requesting this new activation, fail, since other users
	 * should not be allowed to implicitly deactivate private connections
	 * by activating a connection of their own.
	 */
	existing_connection = nm_device_get_applied_connection (device);
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

	/* Final connection must be available on device */
	if (!nm_device_check_connection_available (device, applied, NM_DEVICE_CHECK_CON_AVAILABLE_FOR_USER_REQUEST, NULL)) {
		g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
		             "Connection '%s' is not available on the device %s at this time.",
		             nm_settings_connection_get_id (connection), nm_device_get_iface (device));
		return FALSE;
	}

	/* Create any backing resources the device needs */
	if (!nm_device_is_real (device)) {
		NMDevice *parent;

		parent = find_parent_device_for_connection (self, (NMConnection *) connection, NULL);

		if (parent && !nm_device_is_real (parent)) {
			NMSettingsConnection *parent_con;
			NMActiveConnection *parent_ac;

			parent_con = nm_device_get_best_connection (parent, NULL, error);
			if (!parent_con) {
				g_prefix_error (error, "%s failed to create parent: ", nm_device_get_iface (device));
				return FALSE;
			}

			parent_ac = nm_manager_activate_connection (self, parent_con, NULL, parent, subject, error);
			if (!parent_ac) {
				g_prefix_error (error, "%s failed to activate parent: ", nm_device_get_iface (device));
				return FALSE;
			}

			/* We can't realize now; defer until the parent device is ready. */
			g_signal_connect (active,
			                  NM_ACTIVE_CONNECTION_PARENT_ACTIVE,
			                  (GCallback) active_connection_parent_active,
			                  self);
			nm_active_connection_set_parent (active, parent_ac);
		} else {
			/* We can realize now; no need to wait for a parent device. */
			if (!nm_device_create_and_realize (device, (NMConnection *) connection, parent, error)) {
				g_prefix_error (error, "%s failed to create resources: ", nm_device_get_iface (device));
				return FALSE;
			}
		}
	}

	/* Try to find the master connection/device if the connection has a dependency */
	if (!find_master (self, applied, device,
	                  &master_connection, &master_device, &master_ac,
	                  error)) {
		g_prefix_error (error, "Can not find a master for %s: ",
		                nm_settings_connection_get_id (connection));
		return FALSE;
	}

	/* Ensure there's a master active connection the new connection we're
	 * activating can depend on.
	 */
	if (master_connection || master_device) {
		if (master_connection) {
			_LOGD (LOGD_CORE, "Activation of '%s' requires master connection '%s'",
			       nm_settings_connection_get_id (connection),
			       nm_settings_connection_get_id (master_connection));
		}
		if (master_device) {
			_LOGD (LOGD_CORE, "Activation of '%s' requires master device '%s'",
			       nm_settings_connection_get_id (connection),
			       nm_device_get_ip_iface (master_device));
		}

		/* Ensure eg bond slave and the candidate master is a bond master */
		if (master_connection && !is_compatible_with_slave (NM_CONNECTION (master_connection), applied)) {
			g_set_error (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_DEPENDENCY_FAILED,
			             "The master connection '%s' is not compatible with '%s'",
			             nm_settings_connection_get_id (master_connection),
			             nm_settings_connection_get_id (connection));
			return FALSE;
		}

		if (!master_ac) {
			master_ac = ensure_master_active_connection (self,
			                                             nm_active_connection_get_subject (active),
			                                             applied,
			                                             device,
			                                             master_connection,
			                                             master_device,
			                                             error);
			if (!master_ac) {
				if (master_device) {
					g_prefix_error (error, "Master device '%s' can't be activated: ",
					                nm_device_get_ip_iface (device));
				} else {
					g_prefix_error (error, "Master connection '%s' can't be activated: ",
					                nm_settings_connection_get_id (connection));
				}
				return FALSE;
			}
		}

		nm_active_connection_set_master (active, master_ac);
		_LOGD (LOGD_CORE, "Activation of '%s' depends on active connection %p %s",
		       nm_settings_connection_get_id (connection),
		       master_ac,
		       nm_exported_object_get_path (NM_EXPORTED_OBJECT  (master_ac)) ?: "");
	}

	/* Check slaves for master connection and possibly activate them */
	autoconnect_slaves (self, connection, device, nm_active_connection_get_subject (active));

	/* Disconnect the connection if connected or queued on another device */
	existing = nm_manager_get_connection_device (self, NM_CONNECTION (connection));
	if (existing)
		nm_device_steal_connection (existing, connection);

	/* If the device is there, we can ready it for the activation. */
	if (nm_device_is_real (device))
		unmanaged_to_disconnected (device);

	/* Export the new ActiveConnection to clients and start it on the device */
	nm_exported_object_export (NM_EXPORTED_OBJECT (active));
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
                            NMSettingsConnection *settings_connection,
                            const char *specific_object,
                            NMAuthSubject *subject,
                            GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *parent = NULL;
	NMDevice *device = NULL;

	g_return_val_if_fail (!settings_connection || NM_IS_SETTINGS_CONNECTION (settings_connection), NULL);

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

	return (NMActiveConnection *) nm_vpn_connection_new (settings_connection,
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
	NMSettingsConnection *settings_connection = NULL;
	NMActiveConnection *existing_ac;
	gboolean is_vpn;

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

	is_vpn = nm_connection_is_type (NM_CONNECTION (connection), NM_SETTING_VPN_SETTING_NAME);

	if (NM_IS_SETTINGS_CONNECTION (connection))
		settings_connection = (NMSettingsConnection *) connection;

	if (is_vpn) {
		return _new_vpn_active_connection (self,
		                                   settings_connection,
		                                   specific_object,
		                                   subject,
		                                   error);
	}

	return (NMActiveConnection *) nm_act_request_new (settings_connection,
	                                                  specific_object,
	                                                  subject,
	                                                  device);
}

static void
_internal_activation_failed (NMManager *self,
                             NMActiveConnection *active,
                             const char *error_desc)
{
	_LOGD (LOGD_CORE, "Failed to activate '%s': %s",
	       nm_active_connection_get_settings_connection_id (active),
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
 * @connection: the #NMSettingsConnection to activate on @device
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
                                NMSettingsConnection *connection,
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
	if (!nm_auth_is_subject_in_acl (NM_CONNECTION (connection),
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

		if (   connection == nm_active_connection_get_settings_connection (active)
		    && g_strcmp0 (nm_active_connection_get_specific_object (active), specific_object) == 0
		    && nm_active_connection_get_device (active) == device
		    && nm_auth_subject_is_internal (nm_active_connection_get_subject (active))
		    && nm_auth_subject_is_internal (subject))
			return active;
	}

	active = _new_active_connection (self,
	                                 NM_CONNECTION (connection),
	                                 specific_object,
	                                 device,
	                                 subject,
	                                 error);
	if (active) {
		priv->authorizing_connections = g_slist_prepend (priv->authorizing_connections, active);
		nm_active_connection_authorize (active, NULL, _internal_activation_auth_done, self, NULL);
	}
	return active;
}

/**
 * validate_activation_request:
 * @self: the #NMManager
 * @context: the D-Bus context of the requestor
 * @connection: the partial or complete #NMConnection to be activated
 * @device_path: the object path of the device to be activated, or "/"
 * @out_device: on successful reutrn, the #NMDevice to be activated with @connection
 * @out_vpn: on successful return, %TRUE if @connection is a VPN connection
 * @error: location to store an error on failure
 *
 * Performs basic validation on an activation request, including ensuring that
 * the requestor is a valid Unix process, is not disallowed in @connection
 * permissions, and that a device exists that can activate @connection.
 *
 * Returns: on success, the #NMAuthSubject representing the requestor, or
 *   %NULL on error
 */
static NMAuthSubject *
validate_activation_request (NMManager *self,
                             GDBusMethodInvocation *context,
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
		goto error;
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
		device = nm_manager_get_best_device_for_connection (self, connection, TRUE);

	if (!device && !vpn) {
		gboolean is_software = nm_connection_is_virtual (connection);

		/* VPN and software-device connections don't need a device yet */
		if (!is_software) {
			g_set_error_literal (error,
			                     NM_MANAGER_ERROR,
			                     NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                     "No suitable device found for this connection.");
			goto error;
		}

		if (is_software) {
			char *iface;

			/* Look for an existing device with the connection's interface name */
			iface = nm_manager_get_connection_iface (self, connection, NULL, error);
			if (!iface)
				goto error;

			device = find_device_by_iface (self, iface, connection, NULL);
			g_free (iface);
		}
	}

	if ((!vpn || device_path) && !device) {
		g_set_error_literal (error,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		                     "Failed to find a compatible device for this connection");
		goto error;
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
	GDBusMethodInvocation *context = user_data2;
	GError *error = NULL;
	NMAuthSubject *subject;
	NMSettingsConnection *connection;

	subject = nm_active_connection_get_subject (active);
	connection = nm_active_connection_get_settings_connection (active);

	if (success) {
		if (_internal_activate_generic (self, active, &error)) {
			g_dbus_method_invocation_return_value (context,
			                                       g_variant_new ("(o)",
			                                       nm_exported_object_get_path (NM_EXPORTED_OBJECT (active))));
			nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, TRUE, NULL,
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
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, FALSE, NULL,
	                            subject, error->message);
	_internal_activation_failed (self, active, error->message);

	g_object_unref (active);
	g_dbus_method_invocation_take_error (context, error);
}

static void
impl_manager_activate_connection (NMManager *self,
                                  GDBusMethodInvocation *context,
                                  const char *connection_path,
                                  const char *device_path,
                                  const char *specific_object_path)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *active = NULL;
	NMAuthSubject *subject = NULL;
	NMSettingsConnection *connection = NULL;
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
	if (connection_path) {
		connection = nm_settings_get_connection_by_path (priv->settings, connection_path);
		if (!connection) {
			error = g_error_new_literal (NM_MANAGER_ERROR,
						     NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
						     "Connection could not be found.");
			goto error;
		}
	} else {
		/* If no connection is given, find a suitable connection for the given device path */
		if (!device_path) {
			error = g_error_new_literal (NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                             "Only devices may be activated without a specifying a connection");
			goto error;
		}
		device = nm_manager_get_device_by_path (self, device_path);
		if (!device) {
			error = g_error_new (NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			                     "Can not activate an unknown device '%s'", device_path);
			goto error;
		}

		connection = nm_device_get_best_connection (device, specific_object_path, &error);
		if (!connection)
			goto error;
	}

	subject = validate_activation_request (self,
	                                       context,
	                                       NM_CONNECTION (connection),
	                                       device_path,
	                                       &device,
	                                       &is_vpn,
	                                       &error);
	if (!subject)
		goto error;

	active = _new_active_connection (self,
	                                 NM_CONNECTION (connection),
	                                 specific_object_path,
	                                 device,
	                                 subject,
	                                 &error);
	if (!active)
		goto error;

	nm_active_connection_authorize (active, NULL, _activation_auth_done, self, context);
	g_clear_object (&subject);
	return;

error:
	if (connection) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ACTIVATE, connection, FALSE, NULL,
		                            subject, error->message);
	}
	g_clear_object (&active);
	g_clear_object (&subject);

	g_assert (error);
	g_dbus_method_invocation_take_error (context, error);
}

/***********************************************************************/

typedef struct {
	NMManager *manager;
	NMActiveConnection *active;
} AddAndActivateInfo;

static void
activation_add_done (NMSettings *settings,
                     NMSettingsConnection *new_connection,
                     GError *error,
                     GDBusMethodInvocation *context,
                     NMAuthSubject *subject,
                     gpointer user_data)
{
	AddAndActivateInfo *info = user_data;
	NMManager *self;
	gs_unref_object NMActiveConnection *active = NULL;
	GError *local = NULL;

	self = info->manager;
	active = info->active;
	g_slice_free (AddAndActivateInfo, info);

	if (!error) {
		nm_active_connection_set_settings_connection (active, new_connection);

		if (_internal_activate_generic (self, active, &local)) {
			nm_settings_connection_commit_changes (new_connection,
			                                       NM_SETTINGS_CONNECTION_COMMIT_REASON_USER_ACTION | NM_SETTINGS_CONNECTION_COMMIT_REASON_ID_CHANGED,
			                                       NULL, NULL);
			g_dbus_method_invocation_return_value (
			    context,
			    g_variant_new ("(oo)",
			                   nm_connection_get_path (NM_CONNECTION (new_connection)),
			                   nm_exported_object_get_path (NM_EXPORTED_OBJECT (active))));
			nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE,
			                            nm_active_connection_get_settings_connection (active),
			                            TRUE,
			                            NULL,
			                            nm_active_connection_get_subject (active),
			                            NULL);
			return;
		}
		error = local;
	}

	g_assert (error);
	_internal_activation_failed (self, active, error->message);
	nm_settings_connection_delete (new_connection, NULL, NULL);
	g_dbus_method_invocation_return_gerror (context, error);
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE,
	                            NULL,
	                            FALSE,
	                            NULL,
	                            nm_active_connection_get_subject (active),
	                            error->message);
	g_clear_error (&local);
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
	GDBusMethodInvocation *context = user_data2;
	AddAndActivateInfo *info;
	GError *error = NULL;

	if (success) {
		NMConnection *connection;

		connection = g_object_steal_data (G_OBJECT (active),
		                                  TAG_ACTIVE_CONNETION_ADD_AND_ACTIVATE);

		info = g_slice_new (AddAndActivateInfo);
		info->manager = self;
		info->active = g_object_ref (active);

		/* Basic sender auth checks performed; try to add the connection */
		nm_settings_add_connection_dbus (priv->settings,
		                                 connection,
		                                 FALSE,
		                                 context,
		                                 activation_add_done,
		                                 info);
		g_object_unref (connection);
	} else {
		g_assert (error_desc);
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             error_desc);
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE,
		                            NULL,
		                            FALSE,
		                            NULL,
		                            nm_active_connection_get_subject (active),
		                            error->message);
		g_dbus_method_invocation_take_error (context, error);
	}

	g_object_unref (active);
}

static void
impl_manager_add_and_activate_connection (NMManager *self,
                                          GDBusMethodInvocation *context,
                                          GVariant *settings,
                                          const char *device_path,
                                          const char *specific_object_path)
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
	if (settings && g_variant_n_children (settings))
		_nm_connection_replace_settings (connection, settings, NM_SETTING_PARSE_FLAGS_STRICT, NULL);

	subject = validate_activation_request (self,
	                                       context,
	                                       connection,
	                                       device_path,
	                                       &device,
	                                       &vpn,
	                                       &error);
	if (!subject)
		goto error;

	all_connections = nm_settings_get_connections_sorted (priv->settings);
	if (vpn) {
		/* Try to fill the VPN's connection setting and name at least */
		if (!nm_connection_get_setting_vpn (connection)) {
			error = g_error_new_literal (NM_CONNECTION_ERROR,
			                             NM_CONNECTION_ERROR_MISSING_SETTING,
			                             "VPN connections require a 'vpn' setting");
			g_prefix_error (&error, "%s: ", NM_SETTING_VPN_SETTING_NAME);
			goto error;
		}

		nm_utils_complete_generic (NM_PLATFORM_GET,
		                           connection,
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

	g_object_set_data_full (G_OBJECT (active),
	                        TAG_ACTIVE_CONNETION_ADD_AND_ACTIVATE,
	                        connection,
	                        g_object_unref);

	nm_active_connection_authorize (active, connection, _add_and_activate_auth_done, self, context);
	g_object_unref (subject);
	return;

error:
	nm_audit_log_connection_op (NM_AUDIT_OP_CONN_ADD_ACTIVATE, NULL, FALSE, NULL, subject, error->message);
	g_clear_object (&connection);
	g_slist_free (all_connections);
	g_clear_object (&subject);
	g_clear_object (&active);

	g_assert (error);
	g_dbus_method_invocation_take_error (context, error);
}

/***********************************************************************/

gboolean
nm_manager_deactivate_connection (NMManager *manager,
                                  const char *connection_path,
                                  NMDeviceStateReason reason,
                                  GError **error)
{
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
		if (nm_vpn_connection_deactivate (NM_VPN_CONNECTION (active), vpn_reason, FALSE))
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
		_notify (manager, PROP_ACTIVE_CONNECTIONS);

	return success;
}

static void
deactivate_net_auth_done_cb (NMAuthChain *chain,
                             GError *auth_error,
                             GDBusMethodInvocation *context,
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

	if (auth_error) {
		_LOGD (LOGD_CORE, "Disconnect request failed: %s", auth_error->message);
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
			nm_assert (error);
	}

	active = active_connection_get_by_path (self, path);
	if (active) {
		nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DEACTIVATE,
		                            nm_active_connection_get_settings_connection (active),
		                            !error,
		                            NULL,
		                            nm_auth_chain_get_subject (chain),
		                            error ? error->message : NULL);
	}

	if (error)
		g_dbus_method_invocation_take_error (context, error);
	else
		g_dbus_method_invocation_return_value (context, NULL);

	nm_auth_chain_unref (chain);
}

static void
impl_manager_deactivate_connection (NMManager *self,
                                    GDBusMethodInvocation *context,
                                    const char *active_path)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMActiveConnection *ac;
	NMSettingsConnection *connection = NULL;
	GError *error = NULL;
	NMAuthSubject *subject = NULL;
	NMAuthChain *chain;
	char *error_desc = NULL;

	/* Find the connection by its object path */
	ac = active_connection_get_by_path (self, active_path);
	if (ac)
		connection = nm_active_connection_get_settings_connection (ac);

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
	if (!nm_auth_is_subject_in_acl (NM_CONNECTION (connection),
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
		if (connection) {
			nm_audit_log_connection_op (NM_AUDIT_OP_CONN_DEACTIVATE, connection, FALSE, NULL,
			                            subject, error->message);
		}
		g_dbus_method_invocation_take_error (context, error);
	}
	g_clear_object (&subject);
}

static gboolean
device_is_wake_on_lan (NMDevice *device)
{
	return nm_platform_link_get_wake_on_lan (NM_PLATFORM_GET, nm_device_get_ip_ifindex (device));
}

static gboolean
sleep_devices_add (NMManager *self, NMDevice *device, gboolean suspending)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMSleepMonitorInhibitorHandle *handle = NULL;

	if (g_hash_table_lookup_extended (priv->sleep_devices, device, NULL, (gpointer *) &handle)) {
		if (suspending) {
			/* if we are suspending, always insert a new handle in sleep_devices.
			 * Even if we had an old handle, it might be stale by now. */
			g_hash_table_insert (priv->sleep_devices, device,
			                     nm_sleep_monitor_inhibit_take (priv->sleep_monitor));
			if (handle)
				nm_sleep_monitor_inhibit_release (priv->sleep_monitor, handle);
		}
		return FALSE;
	}

	g_hash_table_insert (priv->sleep_devices,
	                     g_object_ref (device),
	                     suspending
	                         ? nm_sleep_monitor_inhibit_take (priv->sleep_monitor)
	                         : NULL);
	g_signal_connect (device, "notify::" NM_DEVICE_STATE, (GCallback) device_sleep_cb, self);
	return TRUE;
}

static gboolean
sleep_devices_remove (NMManager *self, NMDevice *device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMSleepMonitorInhibitorHandle *handle;

	if (!g_hash_table_lookup_extended (priv->sleep_devices, device, NULL, (gpointer *) &handle))
		return FALSE;

	if (handle)
		nm_sleep_monitor_inhibit_release (priv->sleep_monitor, handle);

	/* Remove device from hash */
	g_signal_handlers_disconnect_by_func (device, device_sleep_cb, self);
	g_hash_table_remove (priv->sleep_devices, device);
	g_object_unref (device);
	return TRUE;
}

static void
sleep_devices_clear (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMDevice *device;
	NMSleepMonitorInhibitorHandle *handle;
	GHashTableIter iter;

	if (!priv->sleep_devices)
		return;

	g_hash_table_iter_init (&iter, priv->sleep_devices);
	while (g_hash_table_iter_next (&iter, (gpointer *) &device, (gpointer *) &handle)) {
		g_signal_handlers_disconnect_by_func (device, device_sleep_cb, self);
		if (handle)
			nm_sleep_monitor_inhibit_release (priv->sleep_monitor, handle);
		g_object_unref (device);
		g_hash_table_iter_remove (&iter);
	}
}

static void
device_sleep_cb (NMDevice *device,
                 GParamSpec *pspec,
                 NMManager *self)
{
	switch (nm_device_get_state (device)) {
	case NM_DEVICE_STATE_DISCONNECTED:
		_LOGD (LOGD_SUSPEND, "sleep: unmanaging device %s", nm_device_get_ip_iface (device));
		nm_device_set_unmanaged_by_flags_queue (device,
		                                        NM_UNMANAGED_SLEEPING,
		                                        TRUE,
		                                        NM_DEVICE_STATE_REASON_SLEEPING);
		break;
	case NM_DEVICE_STATE_UNMANAGED:
		_LOGD (LOGD_SUSPEND, "sleep: device %s is ready", nm_device_get_ip_iface (device));

		if (!sleep_devices_remove (self, device))
			g_return_if_reached ();

		break;
	default:
		return;
	}
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
		_LOGI (LOGD_SUSPEND, "%s...", suspending ? "sleeping" : "disabling");

		/* FIXME: are there still hardware devices that need to be disabled around
		 * suspend/resume?
		 */
		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *device = iter->data;

			/* FIXME: shouldn't we be unmanaging software devices if !suspending? */
			if (nm_device_is_software (device))
				continue;
			/* Wake-on-LAN devices will be taken down post-suspend rather than pre- */
			if (suspending && device_is_wake_on_lan (device)) {
				_LOGD (LOGD_SUSPEND, "sleep: device %s has wake-on-lan, skipping",
				       nm_device_get_ip_iface (device));
				continue;
			}

			if (nm_device_is_activating (device) ||
			    nm_device_get_state (device) == NM_DEVICE_STATE_ACTIVATED) {
				_LOGD (LOGD_SUSPEND, "sleep: wait disconnection of device %s",
				       nm_device_get_ip_iface (device));

				if (sleep_devices_add (self, device, suspending))
					nm_device_queue_state (device, NM_DEVICE_STATE_DEACTIVATING, NM_DEVICE_STATE_REASON_SLEEPING);
			} else {
				nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_SLEEPING, TRUE, NM_DEVICE_STATE_REASON_SLEEPING);
			}
		}
	} else {
		_LOGI (LOGD_SUSPEND, "%s...", waking_from_suspend ? "waking up" : "re-enabling");

		if (waking_from_suspend) {
			sleep_devices_clear (self);
			/* Belatedly take down Wake-on-LAN devices; ideally we wouldn't have to do this
			 * but for now it's the only way to make sure we re-check their connectivity.
			 */
			for (iter = priv->devices; iter; iter = iter->next) {
				NMDevice *device = iter->data;

				if (nm_device_is_software (device))
					continue;
				if (device_is_wake_on_lan (device))
					nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_SLEEPING, TRUE, NM_DEVICE_STATE_REASON_SLEEPING);
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

			if (nm_device_is_software (device)) {
				/* We do not manage/unmanage software devices but
				 * their dhcp leases could have gone stale so we need
				 * to renew them */
				nm_device_update_dynamic_ip_setup (device);
				continue;
			}

			/* enable/disable wireless devices since that we don't respond
			 * to killswitch changes during sleep.
			 */
			for (i = 0; i < RFKILL_TYPE_MAX; i++) {
				RadioState *rstate = &priv->radio_states[i];
				gboolean enabled = radio_enabled_for_rstate (rstate, TRUE);

				if (rstate->desc) {
					_LOGD (LOGD_RFKILL, "%s %s devices (hw_enabled %d, sw_enabled %d, user_enabled %d)",
					       enabled ? "enabling" : "disabling",
					       rstate->desc, rstate->hw_enabled, rstate->sw_enabled, rstate->user_enabled);
				}

				if (nm_device_get_rfkill_type (device) == rstate->rtype)
					nm_device_set_enabled (device, enabled);
			}

			nm_device_set_autoconnect (device, TRUE);

			nm_device_set_unmanaged_by_flags (device, NM_UNMANAGED_SLEEPING, FALSE, NM_DEVICE_STATE_REASON_NOW_MANAGED);
		}
	}

	nm_manager_update_state (self);
}

static void
_internal_sleep (NMManager *self, gboolean do_sleep)
{
	NMManagerPrivate *priv;

	g_return_if_fail (NM_IS_MANAGER (self));

	priv = NM_MANAGER_GET_PRIVATE (self);

	if (priv->sleeping == do_sleep)
		return;

	_LOGI (LOGD_SUSPEND, "%s requested (sleeping: %s  enabled: %s)",
	       do_sleep ? "sleep" : "wake",
	       priv->sleeping ? "yes" : "no",
	       priv->net_enabled ? "yes" : "no");

	priv->sleeping = do_sleep;

	do_sleep_wake (self, TRUE);

	_notify (self, PROP_SLEEPING);
}

#if 0
static void
sleep_auth_done_cb (NMAuthChain *chain,
                    GError *error,
                    GDBusMethodInvocation *context,
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
		_LOGD (LOGD_SUSPEND, "Sleep/wake request failed: %s", error->message);
		ret_error = g_error_new (NM_MANAGER_ERROR,
		                         NM_MANAGER_ERROR_PERMISSION_DENIED,
		                         "Sleep/wake request failed: %s",
		                         error->message);
		g_dbus_method_invocation_take_error (context, ret_error);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		ret_error = g_error_new_literal (NM_MANAGER_ERROR,
		                                 NM_MANAGER_ERROR_PERMISSION_DENIED,
		                                 "Not authorized to sleep/wake");
		g_dbus_method_invocation_take_error (context, ret_error);
	} else {
		/* Auth success */
		do_sleep = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "sleep"));
		_internal_sleep (self, do_sleep);
		g_dbus_method_invocation_return_value (context, NULL);
	}

	nm_auth_chain_unref (chain);
}
#endif

static void
impl_manager_sleep (NMManager *self,
                    GDBusMethodInvocation *context,
                    gboolean do_sleep)
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
		nm_audit_log_control_op (NM_AUDIT_OP_SLEEP_CONTROL, do_sleep ? "on" : "off", FALSE, subject,
		                         error->message);
		g_dbus_method_invocation_take_error (context, error);
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
	g_dbus_method_invocation_return_value (context, NULL);
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
		g_dbus_method_invocation_take_error (context, error);
	}
#endif
}

static void
sleeping_cb (NMSleepMonitor *monitor, gboolean is_about_to_suspend, gpointer user_data)
{
	NMManager *self = user_data;

	_LOGD (LOGD_SUSPEND, "Received %s signal", is_about_to_suspend ? "sleeping" : "resuming");
	_internal_sleep (self, is_about_to_suspend);
}

static void
_internal_enable (NMManager *self, gboolean enable)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	nm_config_state_set (priv->config, TRUE, FALSE,
	                     NM_CONFIG_STATE_PROPERTY_NETWORKING_ENABLED, enable);

	_LOGI (LOGD_SUSPEND, "%s requested (sleeping: %s  enabled: %s)",
	       enable ? "enable" : "disable",
	       priv->sleeping ? "yes" : "no",
	       priv->net_enabled ? "yes" : "no");

	priv->net_enabled = enable;

	do_sleep_wake (self, FALSE);

	_notify (self, PROP_NETWORKING_ENABLED);
}

static void
enable_net_done_cb (NMAuthChain *chain,
                    GError *error,
                    GDBusMethodInvocation *context,
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
		_LOGD (LOGD_CORE, "Enable request failed: %s", error->message);
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
		g_dbus_method_invocation_return_value (context, NULL);
		nm_audit_log_control_op (NM_AUDIT_OP_NET_CONTROL, enable ? "on" : "off", TRUE,
		                         subject, NULL);
	}

	if (ret_error) {
		nm_audit_log_control_op (NM_AUDIT_OP_NET_CONTROL, enable ? "on" : "off", FALSE,
		                         subject, ret_error->message);
		g_dbus_method_invocation_take_error (context, ret_error);
	}

	nm_auth_chain_unref (chain);
}

static void
impl_manager_enable (NMManager *self,
                     GDBusMethodInvocation *context,
                     gboolean enable)
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
		g_dbus_method_invocation_take_error (context, error);
}

/* Permissions */

static void
get_perm_add_result (NMManager *self, NMAuthChain *chain, GVariantBuilder *results, const char *permission)
{
	NMAuthCallResult result;

	result = nm_auth_chain_get_result (chain, permission);
	if (result == NM_AUTH_CALL_RESULT_YES)
		g_variant_builder_add (results, "{ss}", permission, "yes");
	else if (result == NM_AUTH_CALL_RESULT_NO)
		g_variant_builder_add (results, "{ss}", permission, "no");
	else if (result == NM_AUTH_CALL_RESULT_AUTH)
		g_variant_builder_add (results, "{ss}", permission, "auth");
	else {
		_LOGD (LOGD_CORE, "unknown auth chain result %d", result);
	}
}

static void
get_permissions_done_cb (NMAuthChain *chain,
                         GError *error,
                         GDBusMethodInvocation *context,
                         gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *ret_error;
	GVariantBuilder results;

	g_assert (context);

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);
	if (error) {
		_LOGD (LOGD_CORE, "Permissions request failed: %s", error->message);
		ret_error = g_error_new (NM_MANAGER_ERROR,
		                         NM_MANAGER_ERROR_PERMISSION_DENIED,
		                         "Permissions request failed: %s",
		                         error->message);
		g_dbus_method_invocation_take_error (context, ret_error);
	} else {
		g_variant_builder_init (&results, G_VARIANT_TYPE ("a{ss}"));

		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_ENABLE_DISABLE_NETWORK);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_SLEEP_WAKE);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIFI);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_ENABLE_DISABLE_WWAN);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_ENABLE_DISABLE_WIMAX);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_NETWORK_CONTROL);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_WIFI_SHARE_PROTECTED);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_WIFI_SHARE_OPEN);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_SETTINGS_MODIFY_SYSTEM);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_SETTINGS_MODIFY_OWN);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_SETTINGS_MODIFY_HOSTNAME);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_RELOAD);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK);
		get_perm_add_result (self, chain, &results, NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS);

		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(a{ss})", &results));
	}

	nm_auth_chain_unref (chain);
}

static void
impl_manager_get_permissions (NMManager *self,
                              GDBusMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMAuthChain *chain;
	GError *error = NULL;

	chain = nm_auth_chain_new_context (context, get_permissions_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		g_dbus_method_invocation_take_error (context, error);
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
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_RELOAD, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK, FALSE);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS, FALSE);
}

static void
impl_manager_get_state (NMManager *self,
                        GDBusMethodInvocation *context)
{
	nm_manager_update_state (self);
	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(u)", NM_MANAGER_GET_PRIVATE (self)->state));
}

static void
impl_manager_set_logging (NMManager *self,
                          GDBusMethodInvocation *context,
                          const char *level,
                          const char *domains)
{
	GError *error = NULL;

	/* The permission is already enforced by the D-Bus daemon, but we ensure
	 * that the caller is still alive so that clients are forced to wait and
	 * we'll be able to switch to polkit without breaking behavior.
	 */
	if (!nm_bus_manager_ensure_uid (nm_bus_manager_get (),
	                                context,
	                                G_MAXULONG,
	                                NM_MANAGER_ERROR,
	                                NM_MANAGER_ERROR_PERMISSION_DENIED))
		return;

	if (nm_logging_setup (level, domains, NULL, &error)) {
		_LOGI (LOGD_CORE, "logging: level '%s' domains '%s'",
		       nm_logging_level_to_string (), nm_logging_domains_to_string ());
	}

	if (error)
		g_dbus_method_invocation_take_error (context, error);
	else
		g_dbus_method_invocation_return_value (context, NULL);
}

static void
impl_manager_get_logging (NMManager *manager,
                          GDBusMethodInvocation *context)
{
	g_dbus_method_invocation_return_value (context,
	                                       g_variant_new ("(ss)",
	                                                      nm_logging_level_to_string (),
	                                                      nm_logging_domains_to_string ()));
}

static void
connectivity_check_done (GObject *object,
                         GAsyncResult *result,
                         gpointer user_data)
{
	GDBusMethodInvocation *context = user_data;
	NMConnectivityState state;
	GError *error = NULL;

	state = nm_connectivity_check_finish (NM_CONNECTIVITY (object), result, &error);
	if (error)
		g_dbus_method_invocation_take_error (context, error);
	else {
		g_dbus_method_invocation_return_value (context,
		                                       g_variant_new ("(u)", state));
	}
}


static void
check_connectivity_auth_done_cb (NMAuthChain *chain,
                                 GError *auth_error,
                                 GDBusMethodInvocation *context,
                                 gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;
	NMAuthCallResult result;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);

	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL);

	if (auth_error) {
		_LOGD (LOGD_CORE, "CheckConnectivity request failed: %s", auth_error->message);
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

	if (error)
		g_dbus_method_invocation_take_error (context, error);
	nm_auth_chain_unref (chain);
}

static void
impl_manager_check_connectivity (NMManager *self,
                                 GDBusMethodInvocation *context)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMAuthChain *chain;
	GError *error = NULL;

	/* Validate the request */
	chain = nm_auth_chain_new_context (context, check_connectivity_auth_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		g_dbus_method_invocation_take_error (context, error);
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

gboolean
nm_manager_start (NMManager *self, GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter, *connections;
	guint i;

	if (!nm_settings_start (priv->settings, error))
		return FALSE;

	g_signal_connect (NM_PLATFORM_GET,
	                  NM_PLATFORM_SIGNAL_LINK_CHANGED,
	                  G_CALLBACK (platform_link_cb),
	                  self);

	/* Set initial radio enabled/disabled state */
	for (i = 0; i < RFKILL_TYPE_MAX; i++) {
		RadioState *rstate = &priv->radio_states[i];
		gboolean enabled;

		if (!rstate->desc)
			continue;

		/* recheck kernel rfkill state */
		update_rstate_from_rfkill (priv->rfkill_mgr, rstate);

		if (rstate->desc) {
			_LOGI (LOGD_RFKILL, "%s %s by radio killswitch; %s by state file",
			       rstate->desc,
			       (rstate->hw_enabled && rstate->sw_enabled) ? "enabled" : "disabled",
			       rstate->user_enabled ? "enabled" : "disabled");
		}
		enabled = radio_enabled_for_rstate (rstate, TRUE);
		manager_update_radio_enabled (self, rstate, enabled);
	}

	/* Log overall networking status - enabled/disabled */
	_LOGI (LOGD_CORE, "Networking is %s by state file",
	       priv->net_enabled ? "enabled" : "disabled");

	system_unmanaged_devices_changed_cb (priv->settings, NULL, self);
	system_hostname_changed_cb (priv->settings, NULL, self);

	/* Start device factories */
	nm_device_factory_manager_load_factories (_register_device_factory, self);
	nm_device_factory_manager_for_each_factory (start_factory, NULL);

	platform_query_devices (self);

	/* Load VPN plugins */
	priv->vpn_manager = g_object_ref (nm_vpn_manager_get ());

	/* Connections added before the manager is started do not emit
	 * connection-added signals thus devices have to be created manually.
	 */
	_LOGD (LOGD_CORE, "creating virtual devices...");
	connections = nm_settings_get_connections_sorted (priv->settings);
	for (iter = connections; iter; iter = iter->next)
		connection_changed (self, NM_CONNECTION (iter->data));
	g_slist_free (connections);

	priv->devices_inited = TRUE;

	check_if_startup_complete (self);

	return TRUE;
}

void
nm_manager_stop (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	/* Remove all devices */
	while (priv->devices)
		remove_device (self, NM_DEVICE (priv->devices->data), TRUE, TRUE);

	_active_connection_cleanup (self);
}

static gboolean
handle_firmware_changed (gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	priv->fw_changed_id = 0;

	/* Try to re-enable devices with missing firmware */
	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *candidate = NM_DEVICE (iter->data);
		NMDeviceState state = nm_device_get_state (candidate);

		if (   nm_device_get_firmware_missing (candidate)
		    && (state == NM_DEVICE_STATE_UNAVAILABLE)) {
			_LOGI (LOGD_CORE, "(%s): firmware may now be available",
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

	_LOGD (LOGD_CORE, "connectivity checking indicates %s",
	       nm_connectivity_state_to_string (nm_connectivity_get_state (connectivity)));

	nm_manager_update_state (self);
	_notify (self, PROP_CONNECTIVITY);
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
			_LOGI (LOGD_CORE, "kernel firmware directory '%s' changed",
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
		_LOGD (LOGD_CORE, "PrimaryConnection now %s", ac ? nm_active_connection_get_settings_connection_id (ac) : "(none)");
		_notify (self, PROP_PRIMARY_CONNECTION);
		_notify (self, PROP_PRIMARY_CONNECTION_TYPE);
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
		_LOGD (LOGD_CORE, "ActivatingConnection now %s", ac ? nm_active_connection_get_settings_connection_id (ac) : "(none)");
		_notify (self, PROP_ACTIVATING_CONNECTION);
	}
}

#define NM_PERM_DENIED_ERROR "org.freedesktop.NetworkManager.PermissionDenied"

typedef struct {
	NMManager *self;
	GDBusConnection *connection;
	GDBusMessage *message;
	NMAuthSubject *subject;
	const char *permission;
	const char *audit_op;
	char *audit_prop_value;
	GType interface_type;
	const char *glib_propname;
} PropertyFilterData;

static void
free_property_filter_data (PropertyFilterData *pfd)
{
	g_object_unref (pfd->self);
	g_object_unref (pfd->connection);
	g_object_unref (pfd->message);
	g_clear_object (&pfd->subject);
	g_free (pfd->audit_prop_value);
	g_slice_free (PropertyFilterData, pfd);
}

static void
prop_set_auth_done_cb (NMAuthChain *chain,
                       GError *error,
                       GDBusMethodInvocation *context, /* NULL */
                       gpointer user_data)
{
	PropertyFilterData *pfd = user_data;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (pfd->self);
	NMAuthCallResult result;
	GDBusMessage *reply = NULL;
	const char *error_message;
	gs_unref_object NMExportedObject *object = NULL;
	const NMGlobalDnsConfig *global_dns;
	gs_unref_variant GVariant *value = NULL;
	GVariant *args;

	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);
	result = nm_auth_chain_get_result (chain, pfd->permission);
	if (error || (result != NM_AUTH_CALL_RESULT_YES)) {
		reply = g_dbus_message_new_method_error (pfd->message,
		                                         NM_PERM_DENIED_ERROR,
		                                         (error_message = "Not authorized to perform this operation"));
		if (error)
			error_message = error->message;
		goto done;
	}

	object = NM_EXPORTED_OBJECT (nm_bus_manager_get_registered_object (priv->dbus_mgr,
	                                                                   g_dbus_message_get_path (pfd->message)));
	if (!object) {
		reply = g_dbus_message_new_method_error (pfd->message,
		                                         "org.freedesktop.DBus.Error.UnknownObject",
		                                         (error_message = "Object doesn't exist."));
		goto done;
	}

	/* do some extra type checking... */
	if (!nm_exported_object_get_interface_by_type (object, pfd->interface_type)) {
		reply = g_dbus_message_new_method_error (pfd->message,
		                                         "org.freedesktop.DBus.Error.InvalidArgs",
		                                         (error_message = "Object is of unexpected type."));
		goto done;
	}

	args = g_dbus_message_get_body (pfd->message);
	g_variant_get (args, "(&s&sv)", NULL, NULL, &value);
	g_assert (pfd->glib_propname);

	if (!strcmp (pfd->glib_propname, NM_MANAGER_GLOBAL_DNS_CONFIGURATION)) {
		g_assert (g_variant_is_of_type (value, G_VARIANT_TYPE ("a{sv}")));
		global_dns = nm_config_data_get_global_dns_config (nm_config_get_data (priv->config));

		if (global_dns && !nm_global_dns_config_is_internal (global_dns)) {
			reply = g_dbus_message_new_method_error (pfd->message,
			                                         NM_PERM_DENIED_ERROR,
			                                         (error_message = "Global DNS configuration already set via configuration file"));
			goto done;
		}
		/* ... but set the property on the @object itself. It would be correct to set the property
		 * on the skeleton interface, but as it is now, the result is the same. */
		g_object_set (object, pfd->glib_propname, value, NULL);
	} else if (!strcmp (pfd->glib_propname, NM_DEVICE_STATISTICS_REFRESH_RATE_MS)) {
		g_assert (g_variant_is_of_type (value, G_VARIANT_TYPE_UINT32));
		/* the same here */
		g_object_set (object, pfd->glib_propname, (guint) g_variant_get_uint32 (value), NULL);
	} else {
		g_assert (g_variant_is_of_type (value, G_VARIANT_TYPE_BOOLEAN));
		/* the same here */
		g_object_set (object, pfd->glib_propname, g_variant_get_boolean (value), NULL);
	}

	reply = g_dbus_message_new_method_reply (pfd->message);
	g_dbus_message_set_body (reply, g_variant_new_tuple (NULL, 0));
	error_message = NULL;
done:
	nm_audit_log_control_op (pfd->audit_op, pfd->audit_prop_value, !error_message, pfd->subject, error_message);

	g_dbus_connection_send_message (pfd->connection, reply,
	                                G_DBUS_SEND_MESSAGE_FLAGS_NONE,
	                                NULL, NULL);
	g_object_unref (reply);
	nm_auth_chain_unref (chain);

	free_property_filter_data (pfd);
}

static gboolean
do_set_property_check (gpointer user_data)
{
	PropertyFilterData *pfd = user_data;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (pfd->self);
	GDBusMessage *reply = NULL;
	NMAuthChain *chain;
	const char *error_message = NULL;

	pfd->subject = nm_auth_subject_new_unix_process_from_message (pfd->connection, pfd->message);
	if (!pfd->subject) {
		reply = g_dbus_message_new_method_error (pfd->message,
		                                         NM_PERM_DENIED_ERROR,
		                                         (error_message = "Could not determine request UID."));
		goto out;
	}

	/* Validate the user request */
	chain = nm_auth_chain_new_subject (pfd->subject, NULL, prop_set_auth_done_cb, pfd);
	if (!chain) {
		reply = g_dbus_message_new_method_error (pfd->message,
		                                         NM_PERM_DENIED_ERROR,
		                                         (error_message = "Could not authenticate request."));
		goto out;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_add_call (chain, pfd->permission, TRUE);

out:
	if (reply) {
		nm_audit_log_control_op (pfd->audit_op, pfd->audit_prop_value, FALSE, pfd->subject, error_message);
		g_dbus_connection_send_message (pfd->connection, reply,
		                                G_DBUS_SEND_MESSAGE_FLAGS_NONE,
		                                NULL, NULL);
		g_object_unref (reply);
		free_property_filter_data (pfd);
	}

	return FALSE;
}

static GDBusMessage *
prop_filter (GDBusConnection *connection,
             GDBusMessage *message,
             gboolean incoming,
             gpointer user_data)
{
	gs_unref_object NMManager *self = NULL;
	GVariant *args;
	const char *propiface = NULL;
	const char *propname = NULL;
	const char *glib_propname = NULL, *permission = NULL;
	const char *audit_op = NULL;
	GType interface_type = G_TYPE_INVALID;
	PropertyFilterData *pfd;
	const GVariantType *expected_type = G_VARIANT_TYPE_BOOLEAN;
	gs_unref_variant GVariant *value = NULL;

	self = g_weak_ref_get (user_data);
	if (!self)
		return message;

	/* The sole purpose of this function is to validate property accesses on the
	 * NMManager object since gdbus doesn't give us this functionality.
	 */

	/* Only filter org.freedesktop.DBus.Properties.Set calls */
	if (   !incoming
	    || g_dbus_message_get_message_type (message) != G_DBUS_MESSAGE_TYPE_METHOD_CALL
	    || g_strcmp0 (g_dbus_message_get_interface (message), DBUS_INTERFACE_PROPERTIES) != 0
	    || g_strcmp0 (g_dbus_message_get_member (message), "Set") != 0)
		return message;

	args = g_dbus_message_get_body (message);
	if (!g_variant_is_of_type (args, G_VARIANT_TYPE ("(ssv)")))
		return message;
	g_variant_get (args, "(&s&sv)", &propiface, &propname, &value);

	/* Only filter calls to filtered properties, on existing objects */
	if (!strcmp (propiface, NM_DBUS_INTERFACE)) {
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
		} else if (!strcmp (propname, "GlobalDnsConfiguration")) {
			glib_propname = NM_MANAGER_GLOBAL_DNS_CONFIGURATION;
			permission = NM_AUTH_PERMISSION_SETTINGS_MODIFY_GLOBAL_DNS;
			audit_op = NM_AUDIT_OP_NET_CONTROL;
			expected_type = G_VARIANT_TYPE ("a{sv}");
		} else
			return message;
		interface_type = NMDBUS_TYPE_MANAGER_SKELETON;
	} else if (!strcmp (propiface, NM_DBUS_INTERFACE_DEVICE)) {
		if (!strcmp (propname, "Autoconnect")) {
			glib_propname = NM_DEVICE_AUTOCONNECT;
			permission = NM_AUTH_PERMISSION_NETWORK_CONTROL;
			audit_op = NM_AUDIT_OP_DEVICE_AUTOCONNECT;
		} else if (!strcmp (propname, "Managed")) {
			glib_propname = NM_DEVICE_MANAGED;
			permission = NM_AUTH_PERMISSION_NETWORK_CONTROL;
			audit_op = NM_AUDIT_OP_DEVICE_MANAGED;
		} else
			return message;
		interface_type = NMDBUS_TYPE_DEVICE_SKELETON;
	} else if (!strcmp (propiface, NM_DBUS_INTERFACE_DEVICE_STATISTICS)) {
		if (!strcmp (propname, "RefreshRateMs")) {
			glib_propname = NM_DEVICE_STATISTICS_REFRESH_RATE_MS;
			permission = NM_AUTH_PERMISSION_ENABLE_DISABLE_STATISTICS;
			audit_op = NM_AUDIT_OP_STATISTICS;
			expected_type = G_VARIANT_TYPE ("u");
		} else
			return message;
		interface_type = NMDBUS_TYPE_DEVICE_SKELETON;
	} else
		return message;

	if (!g_variant_is_of_type (value, expected_type))
		return message;

	/* This filter function is called from a gdbus worker thread which we can't
	 * make other D-Bus calls from. In particular, we cannot call
	 * org.freedesktop.DBus.GetConnectionUnixUser to find the remote UID.
	 */
	pfd = g_slice_new0 (PropertyFilterData);
	pfd->self = self;
	self = NULL;
	pfd->connection = g_object_ref (connection);
	pfd->message = message;
	pfd->permission = permission;
	pfd->interface_type = interface_type;
	pfd->glib_propname = glib_propname;
	pfd->audit_op = audit_op;
	if (g_variant_is_of_type (value, G_VARIANT_TYPE_BOOLEAN)) {
		pfd->audit_prop_value = g_strdup_printf ("%s:%d", pfd->glib_propname,
		                                         g_variant_get_boolean (value));
	} else
		pfd->audit_prop_value = g_strdup (pfd->glib_propname);

	g_idle_add (do_set_property_check, pfd);

	return NULL;
}

/******************************************************************************/

static int
_set_prop_filter_free2 (gpointer user_data)
{
	g_slice_free (GWeakRef, user_data);
	return G_SOURCE_REMOVE;
}

static void
_set_prop_filter_free (gpointer user_data)
{
	g_weak_ref_clear (user_data);

	/* Delay the final deletion of the user_data. There is a race when
	 * calling g_dbus_connection_remove_filter() that the callback and user_data
	 * might have been copied and being executed after the destroy function
	 * runs (bgo #704568).
	 * This doesn't really fix the race, but it should work well enough. */
	g_timeout_add_seconds (2, _set_prop_filter_free2, user_data);
}

static void
_set_prop_filter (NMManager *self, GDBusConnection *connection)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	nm_assert ((!priv->prop_filter.connection) == (!priv->prop_filter.id));

	if (priv->prop_filter.connection == connection)
		return;

	if (priv->prop_filter.connection) {
		g_dbus_connection_remove_filter (priv->prop_filter.connection, priv->prop_filter.id);
		priv->prop_filter.id = 0;
		g_clear_object (&priv->prop_filter.connection);
	}
	if (connection) {
		GWeakRef *wptr;

		wptr = g_slice_new (GWeakRef);
		g_weak_ref_init  (wptr, self);
		priv->prop_filter.id = g_dbus_connection_add_filter (connection, prop_filter, wptr, _set_prop_filter_free);
		priv->prop_filter.connection = g_object_ref (connection);
	}
}

/******************************************************************************/

static NMCheckpointManager *
_checkpoint_mgr_get (NMManager *self, gboolean create_as_needed)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	if (G_UNLIKELY (!priv->checkpoint_mgr) && create_as_needed)
		priv->checkpoint_mgr = nm_checkpoint_manager_new (self);
	return priv->checkpoint_mgr;
}

static void
checkpoint_auth_done_cb (NMAuthChain *chain,
                         GError *auth_error,
                         GDBusMethodInvocation *context,
                         gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	char *op, *checkpoint_path = NULL, **devices;
	NMCheckpoint *checkpoint;
	NMAuthCallResult result;
	guint32 timeout, flags;
	GVariant *variant = NULL;
	GError *error = NULL;
	const char *arg = NULL;

	op = nm_auth_chain_get_data (chain, "audit-op");
	priv->auth_chains = g_slist_remove (priv->auth_chains, chain);
	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK);

	if (   nm_streq0 (op, NM_AUDIT_OP_CHECKPOINT_DESTROY)
	    || nm_streq0 (op, NM_AUDIT_OP_CHECKPOINT_ROLLBACK))
		arg = checkpoint_path = nm_auth_chain_get_data (chain, "checkpoint_path");

	if (auth_error) {
		error = g_error_new (NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_PERMISSION_DENIED,
		                     "checkpoint check request failed: %s",
		                     auth_error->message);
	} else if (result != NM_AUTH_CALL_RESULT_YES) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Not authorized to checkpoint/rollback");
	} else {
		if (nm_streq0 (op, NM_AUDIT_OP_CHECKPOINT_CREATE)) {
			timeout = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "timeout"));
			flags = GPOINTER_TO_UINT (nm_auth_chain_get_data (chain, "flags"));
			devices = nm_auth_chain_get_data (chain, "devices");

			checkpoint = nm_checkpoint_manager_create (_checkpoint_mgr_get (self, TRUE),
			                                           (const char *const *) devices,
			                                           timeout,
			                                           (NMCheckpointCreateFlags) flags,
			                                           &error);
			if (checkpoint) {
				arg = nm_exported_object_get_path (NM_EXPORTED_OBJECT (checkpoint));
				variant = g_variant_new ("(o)", arg);
			}
		} else if (nm_streq0 (op, NM_AUDIT_OP_CHECKPOINT_DESTROY)) {
			nm_checkpoint_manager_destroy (_checkpoint_mgr_get (self, TRUE),
			                               checkpoint_path, &error);
		} else if (nm_streq0 (op, NM_AUDIT_OP_CHECKPOINT_ROLLBACK)) {
			nm_checkpoint_manager_rollback (_checkpoint_mgr_get (self, TRUE),
			                                checkpoint_path, &variant, &error);
		} else
			g_return_if_reached ();
	}

	nm_audit_log_checkpoint_op (op, arg ?: "", !error, nm_auth_chain_get_subject (chain),
	                            error ? error->message : NULL);

	if (error)
		g_dbus_method_invocation_take_error (context, error);
	else
		g_dbus_method_invocation_return_value (context, variant);


	nm_auth_chain_unref (chain);
}

static void
impl_manager_checkpoint_create (NMManager *self,
                                GDBusMethodInvocation *context,
                                const char *const *devices,
                                guint32 rollback_timeout,
                                guint32 flags)
{
	NMManagerPrivate *priv;
	NMAuthChain *chain;
	GError *error = NULL;

	G_STATIC_ASSERT_EXPR (sizeof (flags) <= sizeof (NMCheckpointCreateFlags));
	g_return_if_fail (NM_IS_MANAGER (self));
	priv = NM_MANAGER_GET_PRIVATE (self);

	chain = nm_auth_chain_new_context (context, checkpoint_auth_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "audit-op", NM_AUDIT_OP_CHECKPOINT_CREATE, NULL);
	nm_auth_chain_set_data (chain, "devices", g_strdupv ((char **) devices), (GDestroyNotify) g_strfreev);
	nm_auth_chain_set_data (chain, "flags",  GUINT_TO_POINTER (flags), NULL);
	nm_auth_chain_set_data (chain, "timeout", GUINT_TO_POINTER (rollback_timeout), NULL);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK, TRUE);
}

static void
impl_manager_checkpoint_destroy (NMManager *self,
                                 GDBusMethodInvocation *context,
                                 const char *checkpoint_path)
{
	NMManagerPrivate *priv;
	GError *error = NULL;
	NMAuthChain *chain;

	g_return_if_fail (NM_IS_MANAGER (self));
	priv = NM_MANAGER_GET_PRIVATE (self);

	chain = nm_auth_chain_new_context (context, checkpoint_auth_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "audit-op", NM_AUDIT_OP_CHECKPOINT_DESTROY, NULL);
	nm_auth_chain_set_data (chain, "checkpoint_path", g_strdup (checkpoint_path), g_free);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK, TRUE);
}

static void
impl_manager_checkpoint_rollback (NMManager *self,
                                  GDBusMethodInvocation *context,
                                  const char *checkpoint_path)
{
	NMManagerPrivate *priv;
	GError *error = NULL;
	NMAuthChain *chain;

	g_return_if_fail (NM_IS_MANAGER (self));
	priv = NM_MANAGER_GET_PRIVATE (self);

	chain = nm_auth_chain_new_context (context, checkpoint_auth_done_cb, self);
	if (!chain) {
		error = g_error_new_literal (NM_MANAGER_ERROR,
		                             NM_MANAGER_ERROR_PERMISSION_DENIED,
		                             "Unable to authenticate request.");
		g_dbus_method_invocation_take_error (context, error);
		return;
	}

	priv->auth_chains = g_slist_append (priv->auth_chains, chain);
	nm_auth_chain_set_data (chain, "audit-op", NM_AUDIT_OP_CHECKPOINT_ROLLBACK, NULL);
	nm_auth_chain_set_data (chain, "checkpoint_path", g_strdup (checkpoint_path), g_free);
	nm_auth_chain_add_call (chain, NM_AUTH_PERMISSION_CHECKPOINT_ROLLBACK, TRUE);
}

/******************************************************************************/

static void
auth_mgr_changed (NMAuthManager *auth_manager, gpointer user_data)
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
rfkill_change (NMManager *self, const char *desc, RfKillType rtype, gboolean enabled)
{
	int fd;
	struct rfkill_event event;
	ssize_t len;

	g_return_if_fail (rtype == RFKILL_TYPE_WLAN || rtype == RFKILL_TYPE_WWAN);

	errno = 0;
	fd = open ("/dev/rfkill", O_RDWR);
	if (fd < 0) {
		if (errno == EACCES)
			_LOGW (LOGD_RFKILL, "(%s): failed to open killswitch device", desc);
		return;
	}

	if (fcntl (fd, F_SETFL, O_NONBLOCK) < 0) {
		_LOGW (LOGD_RFKILL, "(%s): failed to set killswitch device for "
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
		_LOGW (LOGD_RFKILL, "(%s): failed to change WiFi killswitch state: (%d) %s",
		       desc, errno, g_strerror (errno));
	} else if (len == sizeof (event)) {
		_LOGI (LOGD_RFKILL, "%s hardware radio set %s",
		       desc, enabled ? "enabled" : "disabled");
	} else {
		/* Failed to write full structure */
		_LOGW (LOGD_RFKILL, "(%s): failed to change WiFi killswitch state", desc);
	}

	close (fd);
}

static void
manager_radio_user_toggled (NMManager *self,
                            RadioState *rstate,
                            gboolean enabled)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean old_enabled, new_enabled;

	/* Don't touch devices if asleep/networking disabled */
	if (manager_sleeping (self))
		return;

	if (rstate->desc) {
		_LOGD (LOGD_RFKILL, "(%s): setting radio %s by user",
		       rstate->desc,
		       enabled ? "enabled" : "disabled");
	}

	/* Update enabled key in state file */
	nm_config_state_set (priv->config, TRUE, FALSE,
	                     rstate->key, enabled);

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
			rfkill_change (self, rstate->desc, rstate->rtype, new_enabled);

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
			connection = nm_active_connection_get_settings_connection (ac);
			nm_settings_connection_update_timestamp (connection, (guint64) time (NULL), FALSE);
		}
	}

	return TRUE;
}

static void
dbus_connection_changed_cb (NMBusManager *dbus_mgr,
                            GDBusConnection *connection,
                            gpointer user_data)
{
	_set_prop_filter (NM_MANAGER (user_data), connection);
}

/**********************************************************************/

gboolean
nm_manager_check_capability (NMManager *self,
                             NMCapability cap)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	int i;

	for (i = 0; i < priv->capabilities->len; i++) {
		NMCapability test = g_array_index (priv->capabilities, gint, i);
		if (test == cap)
			return TRUE;
		if (test > cap)
			return FALSE;
	}

	return FALSE;
}

static int
cmp_caps (gconstpointer a, gconstpointer b)
{
	return *(gint *)a - *(gint *)b;
}

void
nm_manager_set_capability (NMManager *self,
                           NMCapability cap)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	if (!nm_manager_check_capability (self, cap)) {
		g_array_append_val (priv->capabilities, cap);
		g_array_sort (priv->capabilities, cmp_caps);
		_notify (self, PROP_CAPABILITIES);
	}
}

/**********************************************************************/

NM_DEFINE_SINGLETON_REGISTER (NMManager);

NMManager *
nm_manager_get (void)
{
	g_return_val_if_fail (singleton_instance, NULL);
	return singleton_instance;
}

NMSettings *
nm_settings_get (void)
{
	g_return_val_if_fail (singleton_instance, NULL);

	return NM_MANAGER_GET_PRIVATE (singleton_instance)->settings;
}

NMManager *
nm_manager_setup (void)
{
	NMManager *self;

	g_return_val_if_fail (!singleton_instance, singleton_instance);

	self = g_object_new (NM_TYPE_MANAGER, NULL);
	nm_assert (NM_IS_MANAGER (self));
	singleton_instance = self;

	nm_singleton_instance_register ();
	_LOGD (LOGD_CORE, "setup %s singleton (%p)", "NMManager", singleton_instance);

	nm_exported_object_export ((NMExportedObject *) self);

	return self;
}

static void
constructed (GObject *object)
{
	NMManager *self = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMConfigData *config_data;
	const NMConfigState *state;

	G_OBJECT_CLASS (nm_manager_parent_class)->constructed (object);

	priv->capabilities = g_array_new (FALSE, FALSE, sizeof (gint));

	_set_prop_filter (self, nm_bus_manager_get_connection (priv->dbus_mgr));

	priv->settings = nm_settings_new ();
	g_signal_connect (priv->settings, "notify::" NM_SETTINGS_STARTUP_COMPLETE,
	                  G_CALLBACK (settings_startup_complete_changed), self);
	g_signal_connect (priv->settings, "notify::" NM_SETTINGS_UNMANAGED_SPECS,
	                  G_CALLBACK (system_unmanaged_devices_changed_cb), self);
	g_signal_connect (priv->settings, "notify::" NM_SETTINGS_HOSTNAME,
	                  G_CALLBACK (system_hostname_changed_cb), self);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_ADDED,
	                  G_CALLBACK (connection_added_cb), self);
	g_signal_connect (priv->settings, NM_SETTINGS_SIGNAL_CONNECTION_UPDATED,
	                  G_CALLBACK (connection_updated_cb), self);
	/*
	 * Do not delete existing virtual devices to keep connectivity up.
	 * Virtual devices are reused when NetworkManager is restarted.
	 * Hence, don't react on NM_SETTINGS_SIGNAL_CONNECTION_REMOVED.
	 */

	priv->policy = nm_policy_new (self, priv->settings);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP4_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), self);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_DEFAULT_IP6_DEVICE,
	                  G_CALLBACK (policy_default_device_changed), self);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP4_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), self);
	g_signal_connect (priv->policy, "notify::" NM_POLICY_ACTIVATING_IP6_DEVICE,
	                  G_CALLBACK (policy_activating_device_changed), self);

	priv->config = g_object_ref (nm_config_get ());
	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (_config_changed_cb),
	                  self);

	config_data = nm_config_get_data (priv->config);
	priv->connectivity = nm_connectivity_new (nm_config_data_get_connectivity_uri (config_data),
	                                          nm_config_data_get_connectivity_interval (config_data),
	                                          nm_config_data_get_connectivity_response (config_data));
	g_signal_connect (priv->connectivity, "notify::" NM_CONNECTIVITY_STATE,
	                  G_CALLBACK (connectivity_changed), self);

	state = nm_config_state_get (priv->config);

	priv->net_enabled = state->net_enabled;

	priv->radio_states[RFKILL_TYPE_WLAN].user_enabled = state->wifi_enabled;
	priv->radio_states[RFKILL_TYPE_WWAN].user_enabled = state->wwan_enabled;

	priv->rfkill_mgr = nm_rfkill_manager_new ();
	g_signal_connect (priv->rfkill_mgr,
	                  NM_RFKILL_MANAGER_SIGNAL_RFKILL_CHANGED,
	                  G_CALLBACK (rfkill_manager_rfkill_changed_cb),
	                  self);

	/* Force kernel WiFi/WWAN rfkill state to follow NM saved WiFi/WWAN state
	 * in case the BIOS doesn't save rfkill state, and to be consistent with user
	 * changes to the WirelessEnabled/WWANEnabled properties which toggle kernel
	 * rfkill.
	 */
	rfkill_change (self, priv->radio_states[RFKILL_TYPE_WLAN].desc, RFKILL_TYPE_WLAN, priv->radio_states[RFKILL_TYPE_WLAN].user_enabled);
	rfkill_change (self, priv->radio_states[RFKILL_TYPE_WWAN].desc, RFKILL_TYPE_WWAN, priv->radio_states[RFKILL_TYPE_WWAN].user_enabled);
}

static void
nm_manager_init (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	guint i;
	GFile *file;

	/* Initialize rfkill structures and states */
	memset (priv->radio_states, 0, sizeof (priv->radio_states));

	priv->radio_states[RFKILL_TYPE_WLAN].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WLAN].key = NM_CONFIG_STATE_PROPERTY_WIFI_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].prop = NM_MANAGER_WIRELESS_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].hw_prop = NM_MANAGER_WIRELESS_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WLAN].desc = "WiFi";
	priv->radio_states[RFKILL_TYPE_WLAN].rtype = RFKILL_TYPE_WLAN;

	priv->radio_states[RFKILL_TYPE_WWAN].user_enabled = TRUE;
	priv->radio_states[RFKILL_TYPE_WWAN].key = NM_CONFIG_STATE_PROPERTY_WWAN_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].prop = NM_MANAGER_WWAN_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].hw_prop = NM_MANAGER_WWAN_HARDWARE_ENABLED;
	priv->radio_states[RFKILL_TYPE_WWAN].desc = "WWAN";
	priv->radio_states[RFKILL_TYPE_WWAN].rtype = RFKILL_TYPE_WWAN;

	for (i = 0; i < RFKILL_TYPE_MAX; i++)
		priv->radio_states[i].hw_enabled = TRUE;

	priv->sleeping = FALSE;
	priv->state = NM_STATE_DISCONNECTED;
	priv->startup = TRUE;

	priv->dbus_mgr = g_object_ref (nm_bus_manager_get ());
	g_signal_connect (priv->dbus_mgr,
	                  NM_BUS_MANAGER_DBUS_CONNECTION_CHANGED,
	                  G_CALLBACK (dbus_connection_changed_cb),
	                  self);

	/* sleep/wake handling */
	priv->sleep_monitor = nm_sleep_monitor_new ();
	g_signal_connect (priv->sleep_monitor, NM_SLEEP_MONITOR_SLEEPING,
	                  G_CALLBACK (sleeping_cb), self);

	/* Listen for authorization changes */
	priv->auth_mgr = g_object_ref (nm_auth_manager_get ());
	g_signal_connect (priv->auth_mgr,
	                  NM_AUTH_MANAGER_SIGNAL_CHANGED,
	                  G_CALLBACK (auth_mgr_changed),
	                  self);

	/* Monitor the firmware directory */
	if (strlen (KERNEL_FIRMWARE_DIR)) {
		file = g_file_new_for_path (KERNEL_FIRMWARE_DIR "/");
		priv->fw_monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
		g_object_unref (file);
	}

	if (priv->fw_monitor) {
		g_signal_connect (priv->fw_monitor, "changed",
		                  G_CALLBACK (firmware_dir_changed),
		                  self);
		_LOGI (LOGD_CORE, "monitoring kernel firmware directory '%s'.",
		             KERNEL_FIRMWARE_DIR);
	} else {
		_LOGW (LOGD_CORE, "failed to monitor kernel firmware directory '%s'.",
		       KERNEL_FIRMWARE_DIR);
	}

	/* Update timestamps in active connections */
	priv->timestamp_update_id = g_timeout_add_seconds (300, (GSourceFunc) periodic_update_active_connection_timestamps, self);

	priv->metered = NM_METERED_UNKNOWN;
	priv->sleep_devices = g_hash_table_new (g_direct_hash, g_direct_equal);
}

static gboolean
device_is_real (GObject *device, gpointer user_data)
{
	return nm_device_is_real (NM_DEVICE (device));
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMManager *self = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	NMConfigData *config_data;
	const NMGlobalDnsConfig *dns_config;
	const char *type;

	switch (prop_id) {
	case PROP_VERSION:
		g_value_set_string (value, VERSION);
		break;
	case PROP_CAPABILITIES:
		g_value_set_variant (value, g_variant_new_fixed_array (G_VARIANT_TYPE ("i"),
		                                                       priv->capabilities->data,
		                                                       priv->capabilities->len,
		                                                       sizeof(gint)));
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
		g_value_set_boolean (value, FALSE);
		break;
	case PROP_WIMAX_HARDWARE_ENABLED:
		g_value_set_boolean (value, FALSE);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		nm_utils_g_value_set_object_path_array (value, priv->active_connections, NULL, NULL);
		break;
	case PROP_CONNECTIVITY:
		g_value_set_uint (value, nm_connectivity_get_state (priv->connectivity));
		break;
	case PROP_PRIMARY_CONNECTION:
		nm_utils_g_value_set_object_path (value, priv->primary_connection);
		break;
	case PROP_PRIMARY_CONNECTION_TYPE:
		type = NULL;
		if (priv->primary_connection) {
			NMConnection *con;

			con = nm_active_connection_get_applied_connection (priv->primary_connection);
			if (con)
				type = nm_connection_get_connection_type (con);
		}
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
		nm_utils_g_value_set_object_path_array (value, priv->devices, device_is_real, NULL);
		break;
	case PROP_METERED:
		g_value_set_uint (value, priv->metered);
		break;
	case PROP_GLOBAL_DNS_CONFIGURATION:
		config_data = nm_config_get_data (priv->config);
		dns_config = nm_config_data_get_global_dns_config (config_data);
		nm_global_dns_config_to_dbus (dns_config, value);
		break;
	case PROP_ALL_DEVICES:
		nm_utils_g_value_set_object_path_array (value, priv->devices, NULL, NULL);
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
	NMGlobalDnsConfig *dns_config;
	GError *error = NULL;

	switch (prop_id) {
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
		/* WIMAX is depreacted. This does nothing. */
		break;
	case PROP_GLOBAL_DNS_CONFIGURATION:
		dns_config = nm_global_dns_config_from_dbus (value, &error);
		if (!error)
			nm_config_set_global_dns (priv->config, dns_config, &error);

		nm_global_dns_config_free (dns_config);

		if (error) {
			_LOGD (LOGD_CORE, "set global DNS failed with error: %s", error->message);
			g_error_free (error);
		}
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

	g_slist_free_full (priv->auth_chains, (GDestroyNotify) nm_auth_chain_unref);
	priv->auth_chains = NULL;

	if (priv->checkpoint_mgr) {
		nm_checkpoint_manager_destroy_all (priv->checkpoint_mgr, NULL);
		g_clear_pointer (&priv->checkpoint_mgr, nm_checkpoint_manager_unref);
	}

	if (priv->auth_mgr) {
		g_signal_handlers_disconnect_by_func (priv->auth_mgr,
		                                      G_CALLBACK (auth_mgr_changed),
		                                      manager);
		g_clear_object (&priv->auth_mgr);
	}

	g_assert (priv->devices == NULL);

	nm_clear_g_source (&priv->ac_cleanup_id);

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

	if (priv->settings) {
		g_signal_handlers_disconnect_by_func (priv->settings, settings_startup_complete_changed, manager);
		g_signal_handlers_disconnect_by_func (priv->settings, system_unmanaged_devices_changed_cb, manager);
		g_signal_handlers_disconnect_by_func (priv->settings, system_hostname_changed_cb, manager);
		g_signal_handlers_disconnect_by_func (priv->settings, connection_added_cb, manager);
		g_signal_handlers_disconnect_by_func (priv->settings, connection_updated_cb, manager);
		g_clear_object (&priv->settings);
	}

	g_clear_object (&priv->vpn_manager);

	/* Unregister property filter */
	if (priv->dbus_mgr) {
		g_signal_handlers_disconnect_by_func (priv->dbus_mgr, dbus_connection_changed_cb, manager);
		g_clear_object (&priv->dbus_mgr);
	}
	_set_prop_filter (manager, NULL);

	sleep_devices_clear (manager);
	g_clear_pointer (&priv->sleep_devices, g_hash_table_unref);

	if (priv->sleep_monitor) {
		g_signal_handlers_disconnect_by_func (priv->sleep_monitor, sleeping_cb, manager);
		g_clear_object (&priv->sleep_monitor);
	}

	if (priv->fw_monitor) {
		g_signal_handlers_disconnect_by_func (priv->fw_monitor, firmware_dir_changed, manager);

		nm_clear_g_source (&priv->fw_changed_id);

		g_file_monitor_cancel (priv->fw_monitor);
		g_clear_object (&priv->fw_monitor);
	}

	if (priv->rfkill_mgr) {
		g_signal_handlers_disconnect_by_func (priv->rfkill_mgr, rfkill_manager_rfkill_changed_cb, manager);
		g_clear_object (&priv->rfkill_mgr);
	}

	nm_device_factory_manager_for_each_factory (_deinit_device_factory, manager);

	nm_clear_g_source (&priv->timestamp_update_id);

	g_array_free (priv->capabilities, TRUE);

	G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
}

static void
nm_manager_class_init (NMManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (manager_class);

	exported_object_class->export_path = NM_DBUS_PATH;

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
	obj_properties[PROP_VERSION] =
	    g_param_spec_string (NM_MANAGER_VERSION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CAPABILITIES] =
		g_param_spec_variant (NM_MANAGER_CAPABILITIES, "", "",
		                      G_VARIANT_TYPE ("au"),
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STATE] =
	    g_param_spec_uint (NM_MANAGER_STATE, "", "",
	                       0, NM_STATE_DISCONNECTED, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STARTUP] =
	    g_param_spec_boolean (NM_MANAGER_STARTUP, "", "",
	                          TRUE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_NETWORKING_ENABLED] =
	    g_param_spec_boolean (NM_MANAGER_NETWORKING_ENABLED, "", "",
	                          TRUE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WIRELESS_ENABLED] =
	    g_param_spec_boolean (NM_MANAGER_WIRELESS_ENABLED, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WIRELESS_HARDWARE_ENABLED] =
	    g_param_spec_boolean (NM_MANAGER_WIRELESS_HARDWARE_ENABLED, "", "",
	                          TRUE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WWAN_ENABLED] =
	    g_param_spec_boolean (NM_MANAGER_WWAN_ENABLED, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WWAN_HARDWARE_ENABLED] =
	    g_param_spec_boolean (NM_MANAGER_WWAN_HARDWARE_ENABLED, "", "",
	                          TRUE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WIMAX_ENABLED] =
	    g_param_spec_boolean (NM_MANAGER_WIMAX_ENABLED, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_WIMAX_HARDWARE_ENABLED] =
	    g_param_spec_boolean (NM_MANAGER_WIMAX_HARDWARE_ENABLED, "", "",
	                          TRUE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ACTIVE_CONNECTIONS] =
	    g_param_spec_boxed (NM_MANAGER_ACTIVE_CONNECTIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONNECTIVITY] =
	    g_param_spec_uint (NM_MANAGER_CONNECTIVITY, "", "",
	                       NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_PRIMARY_CONNECTION] =
	    g_param_spec_string (NM_MANAGER_PRIMARY_CONNECTION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_PRIMARY_CONNECTION_TYPE] =
	    g_param_spec_string (NM_MANAGER_PRIMARY_CONNECTION_TYPE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ACTIVATING_CONNECTION] =
	    g_param_spec_string (NM_MANAGER_ACTIVATING_CONNECTION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/* Hostname is not exported over D-Bus */
	obj_properties[PROP_HOSTNAME] =
	    g_param_spec_string (NM_MANAGER_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/* Sleeping is not exported over D-Bus */
	obj_properties[PROP_SLEEPING] =
	    g_param_spec_boolean (NM_MANAGER_SLEEPING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DEVICES] =
	    g_param_spec_boxed (NM_MANAGER_DEVICES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMManager:metered:
	 *
	 * Whether the connectivity is metered.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_METERED] =
	    g_param_spec_uint (NM_MANAGER_METERED, "", "",
	                       0, G_MAXUINT32, NM_METERED_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMManager:global-dns-configuration:
	 *
	 * The global DNS configuration.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_GLOBAL_DNS_CONFIGURATION] =
	    g_param_spec_variant (NM_MANAGER_GLOBAL_DNS_CONFIGURATION, "", "",
	                          G_VARIANT_TYPE ("a{sv}"),
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMManager:all-devices:
	 *
	 * All devices, including those that are not realized.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_ALL_DEVICES] =
	    g_param_spec_boxed (NM_MANAGER_ALL_DEVICES, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	/* signals */

	/* D-Bus exported; emitted only for realized devices */
	signals[DEVICE_ADDED] =
	    g_signal_new (NM_MANAGER_DEVICE_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_DEVICE);

	/* Emitted for both realized devices and placeholder devices */
	signals[INTERNAL_DEVICE_ADDED] =
	    g_signal_new (NM_MANAGER_INTERNAL_DEVICE_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST, 0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_OBJECT);

	/* D-Bus exported; emitted only for realized devices when a device
	 * becomes unrealized or removed */
	signals[DEVICE_REMOVED] =
	    g_signal_new (NM_MANAGER_DEVICE_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_DEVICE);

	/* Emitted for both realized devices and placeholder devices */
	signals[INTERNAL_DEVICE_REMOVED] =
	    g_signal_new (NM_MANAGER_INTERNAL_DEVICE_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST, 0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_OBJECT);

	signals[STATE_CHANGED] =
	    g_signal_new (NM_MANAGER_STATE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[CHECK_PERMISSIONS] =
	    g_signal_new (NM_MANAGER_CHECK_PERMISSIONS,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	signals[ACTIVE_CONNECTION_ADDED] =
	    g_signal_new (NM_MANAGER_ACTIVE_CONNECTION_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_ACTIVE_CONNECTION);

	signals[ACTIVE_CONNECTION_REMOVED] =
	    g_signal_new (NM_MANAGER_ACTIVE_CONNECTION_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_ACTIVE_CONNECTION);

	signals[CONFIGURE_QUIT] =
	    g_signal_new (NM_MANAGER_CONFIGURE_QUIT,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (manager_class),
	                                        NMDBUS_TYPE_MANAGER_SKELETON,
	                                        "Reload", impl_manager_reload,
	                                        "GetDevices", impl_manager_get_devices,
	                                        "GetAllDevices", impl_manager_get_all_devices,
	                                        "GetDeviceByIpIface", impl_manager_get_device_by_ip_iface,
	                                        "ActivateConnection", impl_manager_activate_connection,
	                                        "AddAndActivateConnection", impl_manager_add_and_activate_connection,
	                                        "DeactivateConnection", impl_manager_deactivate_connection,
	                                        "Sleep", impl_manager_sleep,
	                                        "Enable", impl_manager_enable,
	                                        "GetPermissions", impl_manager_get_permissions,
	                                        "SetLogging", impl_manager_set_logging,
	                                        "GetLogging", impl_manager_get_logging,
	                                        "CheckConnectivity", impl_manager_check_connectivity,
	                                        "state", impl_manager_get_state,
	                                        "CheckpointCreate", impl_manager_checkpoint_create,
	                                        "CheckpointDestroy", impl_manager_checkpoint_destroy,
	                                        "CheckpointRollback", impl_manager_checkpoint_rollback,
	                                        NULL);
}
