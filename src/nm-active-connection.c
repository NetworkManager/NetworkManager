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
 * Copyright (C) 2008 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-active-connection.h"

#include "nm-common-macros.h"
#include "nm-dbus-interface.h"
#include "devices/nm-device.h"
#include "settings/nm-settings-connection.h"
#include "nm-simple-connection.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"

#include "introspection/org.freedesktop.NetworkManager.Connection.Active.h"

typedef struct _NMActiveConnectionPrivate {
	NMSettingsConnection *settings_connection;
	NMConnection *applied_connection;
	char *specific_object;
	NMDevice *device;

	guint64 version_id;

	char *pending_activation_id;

	NMActivationStateFlags state_flags;

	NMActiveConnectionState state;
	bool is_default:1;
	bool is_default6:1;
	bool state_set:1;
	bool vpn:1;
	bool master_ready:1;

	NMActivationType activation_type:3;

	NMAuthSubject *subject;
	NMActiveConnection *master;

	NMActiveConnection *parent;

	NMAuthChain *chain;
	const char *wifi_shared_permission;
	NMActiveConnectionAuthResultFunc result_func;
	gpointer user_data1;
	gpointer user_data2;
} NMActiveConnectionPrivate;

NM_GOBJECT_PROPERTIES_DEFINE (NMActiveConnection,
	PROP_CONNECTION,
	PROP_ID,
	PROP_UUID,
	PROP_TYPE,
	PROP_SPECIFIC_OBJECT,
	PROP_DEVICES,
	PROP_STATE,
	PROP_STATE_FLAGS,
	PROP_DEFAULT,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_DEFAULT6,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,
	PROP_VPN,
	PROP_MASTER,

	PROP_INT_SETTINGS_CONNECTION,
	PROP_INT_APPLIED_CONNECTION,
	PROP_INT_DEVICE,
	PROP_INT_SUBJECT,
	PROP_INT_MASTER,
	PROP_INT_MASTER_READY,
	PROP_INT_ACTIVATION_TYPE,
);

enum {
	DEVICE_CHANGED,
	DEVICE_METERED_CHANGED,
	PARENT_ACTIVE,
	STATE_CHANGED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

G_DEFINE_ABSTRACT_TYPE (NMActiveConnection, nm_active_connection, NM_TYPE_EXPORTED_OBJECT)

#define NM_ACTIVE_CONNECTION_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMActiveConnection, NM_IS_ACTIVE_CONNECTION)

/*****************************************************************************/

static void check_master_ready (NMActiveConnection *self);
static void _device_cleanup (NMActiveConnection *self);
static void _settings_connection_notify_flags (NMSettingsConnection *settings_connection,
                                               GParamSpec *param,
                                               NMActiveConnection *self);
static void _set_activation_type_managed (NMActiveConnection *self);

/*****************************************************************************/

#define _NMLOG_DOMAIN         LOGD_DEVICE
#define _NMLOG_PREFIX_NAME    "active-connection"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        char _sbuf[64]; \
        NMActiveConnectionPrivate *_priv = self ? NM_ACTIVE_CONNECTION_GET_PRIVATE (self) : NULL; \
        \
        nm_log ((level), _NMLOG_DOMAIN, \
                (_priv && _priv->device) ? nm_device_get_iface (_priv->device) : NULL, \
                (_priv && _priv->applied_connection) ? nm_connection_get_uuid (_priv->applied_connection) : NULL, \
                "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                _NMLOG_PREFIX_NAME, \
                self ? nm_sprintf_buf (_sbuf, "[%p]", self) : "" \
                _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_state_to_string, NMActiveConnectionState,
	NM_UTILS_LOOKUP_DEFAULT (NULL),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVE_CONNECTION_STATE_UNKNOWN,      "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVE_CONNECTION_STATE_ACTIVATING,   "activating"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVE_CONNECTION_STATE_ACTIVATED,    "activated"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVE_CONNECTION_STATE_DEACTIVATING, "deactivating"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_ACTIVE_CONNECTION_STATE_DEACTIVATED,  "deactivated"),
);
#define state_to_string(state) NM_UTILS_LOOKUP_STR (_state_to_string, state)

NM_UTILS_FLAGS2STR_DEFINE_STATIC (_state_flags_to_string, NMActivationStateFlags,
	NM_UTILS_FLAGS2STR (NM_ACTIVATION_STATE_FLAG_NONE,                 "none"),
	NM_UTILS_FLAGS2STR (NM_ACTIVATION_STATE_FLAG_IS_MASTER,            "is-master"),
	NM_UTILS_FLAGS2STR (NM_ACTIVATION_STATE_FLAG_IS_SLAVE,             "is-slave"),
	NM_UTILS_FLAGS2STR (NM_ACTIVATION_STATE_FLAG_LAYER2_READY,         "layer2-ready"),
	NM_UTILS_FLAGS2STR (NM_ACTIVATION_STATE_FLAG_IP4_READY,            "ip4-ready"),
	NM_UTILS_FLAGS2STR (NM_ACTIVATION_STATE_FLAG_IP6_READY,            "ip6-ready"),
	NM_UTILS_FLAGS2STR (NM_ACTIVATION_STATE_FLAG_MASTER_HAS_SLAVES,    "master-has-slaves"),
);

/*****************************************************************************/

static void
_settings_connection_updated (NMSettingsConnection *connection,
                              gboolean by_user,
                              gpointer user_data)
{
	NMActiveConnection *self = user_data;

	/* we don't know which properties actually changed. Just to be sure,
	 * notify about all possible properties. After all, an update of a
	 * connection is a rare event. */

	_notify (self, PROP_ID);

	/* it's a bit odd to update the TYPE of an active connection. But the alternative
	 * is unexpected too. */
	_notify (self, PROP_TYPE);

	/* currently, the UUID and the exported CONNECTION path cannot change. Later, we might
	 * want to support a re-link operation, which associates an active-connection with a different
	 * settings-connection. */
}

static void
_settings_connection_removed (NMSettingsConnection *connection,
                              gpointer user_data)
{
	NMActiveConnection *self = user_data;

	/* Our settings connection is about to drop off. The next active connection
	 * cleanup is going to tear us down (at least until we grow the capability to
	 * re-link; in that case we'd just clean the references to the old connection here).
	 * Let's remove ourselves from the bus so that we're not exposed with a dangling
	 * reference to the setting connection once it's gone. */
	if (nm_exported_object_is_exported (NM_EXPORTED_OBJECT (self)))
		nm_exported_object_unexport (NM_EXPORTED_OBJECT (self));
}

static void
_set_settings_connection (NMActiveConnection *self, NMSettingsConnection *connection)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (priv->settings_connection == connection)
		return;
	if (priv->settings_connection) {
		g_signal_handlers_disconnect_by_func (priv->settings_connection, _settings_connection_updated, self);
		g_signal_handlers_disconnect_by_func (priv->settings_connection, _settings_connection_removed, self);
		g_signal_handlers_disconnect_by_func (priv->settings_connection, _settings_connection_notify_flags, self);
		g_clear_object (&priv->settings_connection);
	}
	if (connection) {
		priv->settings_connection = g_object_ref (connection);
		g_signal_connect (connection, NM_SETTINGS_CONNECTION_UPDATED_INTERNAL, (GCallback) _settings_connection_updated, self);
		g_signal_connect (connection, NM_SETTINGS_CONNECTION_REMOVED, (GCallback) _settings_connection_removed, self);
		if (nm_active_connection_get_activation_type (self) == NM_ACTIVATION_TYPE_EXTERNAL)
			g_signal_connect (connection, "notify::"NM_SETTINGS_CONNECTION_FLAGS, (GCallback) _settings_connection_notify_flags, self);
	}
}

NMActiveConnectionState
nm_active_connection_get_state (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->state;
}

void
nm_active_connection_set_state (NMActiveConnection *self,
                                NMActiveConnectionState new_state,
                                NMActiveConnectionStateReason reason)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	NMActiveConnectionState old_state;

	if (priv->state == new_state)
		return;

	/* DEACTIVATED is a terminal state */
	if (priv->state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		g_return_if_fail (new_state != NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);

	_LOGD ("set state %s (was %s)",
	       state_to_string (new_state),
	       state_to_string (priv->state));

	if (   new_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    && priv->activation_type == NM_ACTIVATION_TYPE_ASSUME) {
		/* assuming connections mean to gracefully take over an externally
		 * configured device. Once activation is complete, an assumed
		 * activation *is* the same as a full activation. */
		_set_activation_type_managed (self);
	}

	old_state = priv->state;
	priv->state = new_state;
	priv->state_set = TRUE;
	g_signal_emit (self, signals[STATE_CHANGED], 0, (guint) new_state, (guint) reason);
	_notify (self, PROP_STATE);

	check_master_ready (self);

	if (   new_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    || old_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		nm_settings_connection_update_timestamp (priv->settings_connection,
		                                         (guint64) time (NULL), TRUE);
	}

	if (priv->device) {
		if (   old_state < NM_ACTIVE_CONNECTION_STATE_ACTIVATED
		    && new_state >= NM_ACTIVE_CONNECTION_STATE_ACTIVATED &&
		    priv->pending_activation_id)
		{
			nm_device_remove_pending_action (priv->device, priv->pending_activation_id, TRUE);
			g_clear_pointer (&priv->pending_activation_id, g_free);
		}
	}

	if (   new_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    || old_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		_notify (self, PROP_IP4_CONFIG);
		_notify (self, PROP_DHCP4_CONFIG);
		_notify (self, PROP_IP6_CONFIG);
		_notify (self, PROP_DHCP6_CONFIG);
	}

	if (priv->state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		/* Device is no longer relevant when deactivated. So remove it and
		 * emit property change notification so clients re-read the value,
		 * which will be NULL due to conditions in get_property().
		 */
		_device_cleanup (self);
		_notify (self, PROP_DEVICES);
	}
}

void
nm_active_connection_set_state_fail (NMActiveConnection *self,
                                     NMActiveConnectionStateReason reason,
                                     const char *error_desc)
{
	NMActiveConnectionState s;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));

	if (error_desc) {
		_LOGD ("Failed to activate '%s': %s",
		       nm_active_connection_get_settings_connection_id (self),
		       error_desc);
	}

	s = nm_active_connection_get_state (self);
	if (   s >= NM_ACTIVE_CONNECTION_STATE_ACTIVATING
	    && s < NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
		nm_active_connection_set_state (self,
		                                NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
		                                reason);
		s = nm_active_connection_get_state (self);
	}
	if (s < NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		nm_active_connection_set_state (self,
		                                NM_ACTIVE_CONNECTION_STATE_DEACTIVATED,
		                                reason);
	}
}

NMActivationStateFlags
nm_active_connection_get_state_flags (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->state_flags;
}

void
nm_active_connection_set_state_flags_full (NMActiveConnection *self,
                                           NMActivationStateFlags state_flags,
                                           NMActivationStateFlags mask)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	NMActivationStateFlags f;

	f = (priv->state_flags & ~mask) | (state_flags & mask);
	if (f != priv->state_flags) {
		char buf1[G_N_ELEMENTS (_nm_utils_to_string_buffer)];
		char buf2[G_N_ELEMENTS (_nm_utils_to_string_buffer)];

		_LOGD ("set state-flags %s (was %s)",
		       _state_flags_to_string (f, buf1, sizeof (buf1)),
		       _state_flags_to_string (priv->state_flags, buf2, sizeof (buf2)));
		priv->state_flags = f;
		_notify (self, PROP_STATE_FLAGS);
	}
}

const char *
nm_active_connection_get_settings_connection_id (NMActiveConnection *self)
{
	NMSettingsConnection *con;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	con = NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->settings_connection;
	return con
	       ? nm_connection_get_id (NM_CONNECTION (con))
	       : NULL;
}

NMSettingsConnection *
_nm_active_connection_get_settings_connection (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->settings_connection;
}

NMSettingsConnection *
nm_active_connection_get_settings_connection (NMActiveConnection *self)
{
	NMSettingsConnection *con;

	con = _nm_active_connection_get_settings_connection (self);

	/* Only call this function on an active-connection that is already
	 * fully set-up (i.e. that has a settings-connection). Other uses
	 * indicate a bug. */
	g_return_val_if_fail (con, NULL);
	return con;
}

NMConnection *
nm_active_connection_get_applied_connection (NMActiveConnection *self)
{
	NMConnection *con;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	con = NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->applied_connection;

	/* Only call this function on an active-connection that is already
	 * fully set-up (i.e. that has a settings-connection). Other uses
	 * indicate a bug. */
	g_return_val_if_fail (con, NULL);
	return con;
}

static void
_set_applied_connection_take (NMActiveConnection *self,
                              NMConnection *applied_connection)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	NMActivationStateFlags flags_val = 0;

	nm_assert (NM_IS_CONNECTION (applied_connection));
	nm_assert (!priv->applied_connection);

	/* we take ownership of @applied_connection. Ensure to pass in a reference. */
	priv->applied_connection = applied_connection;
	nm_connection_clear_secrets (priv->applied_connection);

	/* we determine whether the connection is a master/slave, based solely
	 * on the connection properties itself. */
	s_con = nm_connection_get_setting_connection (priv->applied_connection);
	if (nm_setting_connection_get_master (s_con))
		flags_val |= NM_ACTIVATION_STATE_FLAG_IS_SLAVE;

	if (NM_IN_STRSET (nm_setting_connection_get_connection_type (s_con),
	                  NM_SETTING_BOND_SETTING_NAME,
	                  NM_SETTING_BRIDGE_SETTING_NAME,
	                  NM_SETTING_TEAM_SETTING_NAME))
		flags_val |= NM_ACTIVATION_STATE_FLAG_IS_MASTER;

	nm_active_connection_set_state_flags_full (self,
	                                           flags_val,
	                                             NM_ACTIVATION_STATE_FLAG_IS_MASTER
	                                           | NM_ACTIVATION_STATE_FLAG_IS_SLAVE);
}

void
nm_active_connection_set_settings_connection (NMActiveConnection *self,
                                              NMSettingsConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	g_return_if_fail (NM_IS_SETTINGS_CONNECTION (connection));
	g_return_if_fail (!priv->settings_connection);
	g_return_if_fail (!priv->applied_connection);

	/* Can't change connection after the ActiveConnection is exported over D-Bus.
	 *
	 * Later, we want to change the settings-connection of an activated connection.
	 * When doing that, this changes the assumption that the settings-connection
	 * never changes (once it's set). That has effects for NMVpnConnection and
	 * NMActivationRequest.
	 * For example, we'd have to cancel all pending seret requests. */
	g_return_if_fail (!nm_exported_object_is_exported (NM_EXPORTED_OBJECT (self)));

	_set_settings_connection (self, connection);

	_set_applied_connection_take (self,
	                              nm_simple_connection_new_clone (NM_CONNECTION (priv->settings_connection)));
}

gboolean
nm_active_connection_has_unmodified_applied_connection (NMActiveConnection *self, NMSettingCompareFlags compare_flags)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	g_return_val_if_fail (priv->settings_connection, FALSE);

	return nm_settings_connection_has_unmodified_applied_connection (priv->settings_connection,
	                                                                 priv->applied_connection,
	                                                                 compare_flags);
}

/*****************************************************************************/

void
nm_active_connection_clear_secrets (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (nm_settings_connection_has_unmodified_applied_connection (priv->settings_connection,
	                                                              priv->applied_connection,
	                                                              NM_SETTING_COMPARE_FLAG_NONE))
		nm_connection_clear_secrets ((NMConnection *) priv->settings_connection);
	nm_connection_clear_secrets (priv->applied_connection);
}

/*****************************************************************************/

const char *
nm_active_connection_get_specific_object (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->specific_object;
}

void
nm_active_connection_set_specific_object (NMActiveConnection *self,
                                          const char *specific_object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	/* Nothing that calls this function should be using paths from D-Bus,
	 * where NM uses "/" to mean NULL.
	 */
	g_assert (g_strcmp0 (specific_object, "/") != 0);

	if (g_strcmp0 (priv->specific_object, specific_object) == 0)
		return;

	g_free (priv->specific_object);
	priv->specific_object = g_strdup (specific_object);
	_notify (self, PROP_SPECIFIC_OBJECT);
}

void
nm_active_connection_set_default (NMActiveConnection *self,
                                  int addr_family,
                                  gboolean is_default)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));
	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET, AF_INET6));

	is_default = !!is_default;

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET)) {
		if (priv->is_default != is_default) {
			priv->is_default = is_default;
			_notify (self, PROP_DEFAULT);
		}
	}
	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET6)) {
		if (priv->is_default6 != is_default) {
			priv->is_default6 = is_default;
			_notify (self, PROP_DEFAULT6);
		}
	}
}

gboolean
nm_active_connection_get_default (NMActiveConnection *self, int addr_family)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);
	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET, AF_INET6));

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	switch (addr_family) {
	case AF_INET:   return priv->is_default;
	case AF_INET6:  return priv->is_default6;
	default:        return priv->is_default || priv->is_default6;
	}
}

NMAuthSubject *
nm_active_connection_get_subject (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->subject;
}

gboolean
nm_active_connection_get_user_requested (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return nm_auth_subject_is_unix_process (NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->subject);
}

NMDevice *
nm_active_connection_get_device (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->device;
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (user_data);
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	/* When already deactivated or before activation, device state changes are useless */
	if (priv->state >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		return;
	if (old_state < NM_DEVICE_STATE_DISCONNECTED)
		return;

	/* Let subclasses handle the state change */
	if (NM_ACTIVE_CONNECTION_GET_CLASS (self)->device_state_changed)
		NM_ACTIVE_CONNECTION_GET_CLASS (self)->device_state_changed (self, device, new_state, old_state);
}

static void
device_master_changed (GObject *object,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	NMDevice *device = NM_DEVICE (object);
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (user_data);
	NMActiveConnection *master;
	NMActiveConnectionState master_state;

	if (NM_ACTIVE_CONNECTION (nm_device_get_act_request (device)) != self)
		return;
	if (!nm_device_get_master (device))
		return;
	if (!nm_active_connection_get_master (self))
		return;
	g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_master_changed), self);

	master = nm_active_connection_get_master (self);
	master_state = nm_active_connection_get_state (master);
	if (master_state >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING) {
		/* Master failed before attaching the slave */
		if (NM_ACTIVE_CONNECTION_GET_CLASS (self)->master_failed)
			NM_ACTIVE_CONNECTION_GET_CLASS (self)->master_failed (self);
	}
}

static void
device_metered_changed (GObject *object,
                        GParamSpec *pspec,
                        gpointer user_data)
{
	NMActiveConnection *self = (NMActiveConnection *) user_data;
	NMDevice *device = NM_DEVICE (object);

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));
	g_signal_emit (self, signals[DEVICE_METERED_CHANGED], 0, nm_device_get_metered (device));
}

gboolean
nm_active_connection_set_device (NMActiveConnection *self, NMDevice *device)
{
	NMActiveConnectionPrivate *priv;
	gs_unref_object NMDevice *old_device = NULL;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);
	g_return_val_if_fail (!device || NM_IS_DEVICE (device), FALSE);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	if (device == priv->device)
		return TRUE;

	_LOGD ("set device %s%s%s [%p]",
	       NM_PRINT_FMT_QUOTED (device && nm_device_get_iface (device),
	                            "\"",
	                            nm_device_get_iface (device),
	                            "\"",
	                            device ? "(unknown)" : "(null)"),
	       device);

	old_device = priv->device ? g_object_ref (priv->device) : NULL;
	_device_cleanup (self);

	if (device) {
		/* Device obviously can't be its own master */
		g_return_val_if_fail (!priv->master || device != nm_active_connection_get_device (priv->master), FALSE);

		priv->device = g_object_ref (device);

		g_signal_connect (device, NM_DEVICE_STATE_CHANGED,
		                  G_CALLBACK (device_state_changed), self);
		g_signal_connect (device, "notify::" NM_DEVICE_MASTER,
		                  G_CALLBACK (device_master_changed), self);
		g_signal_connect (device, "notify::" NM_DEVICE_METERED,
		                  G_CALLBACK (device_metered_changed), self);

		if (priv->activation_type != NM_ACTIVATION_TYPE_EXTERNAL) {
			priv->pending_activation_id = g_strdup_printf (NM_PENDING_ACTIONPREFIX_ACTIVATION"%p", (void *)self);
			nm_device_add_pending_action (device, priv->pending_activation_id, TRUE);
		}
	} else {
		/* The ActiveConnection's device can only be cleared after the
		 * connection is activated.
		 */
		g_warn_if_fail (priv->state > NM_ACTIVE_CONNECTION_STATE_UNKNOWN);
		priv->device = NULL;
	}
	_notify (self, PROP_INT_DEVICE);

	g_signal_emit (self, signals[DEVICE_CHANGED], 0, priv->device, old_device);

	_notify (self, PROP_DEVICES);

	return TRUE;
}

NMActiveConnection *
nm_active_connection_get_master (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->master;
}

/**
 * nm_active_connection_get_master_ready:
 * @self: the #NMActiveConnection
 *
 * Returns: %TRUE if the connection has a master connection, and that
 * master connection is ready to accept slaves.  Otherwise %FALSE.
 */
gboolean
nm_active_connection_get_master_ready (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->master_ready;
}

static void
check_master_ready (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	gboolean signalling = FALSE;

	/* ActiveConnetions don't enter the ACTIVATING state until they have a
	 * NMDevice in PREPARE or higher states, so the master active connection's
	 * device will be ready to accept slaves when the master is in ACTIVATING
	 * or higher states.
	 */
	if (   !priv->master_ready
	    && priv->master
	    && priv->state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING
	    && NM_IN_SET (nm_active_connection_get_state (priv->master),
	                  NM_ACTIVE_CONNECTION_STATE_ACTIVATING,
	                  NM_ACTIVE_CONNECTION_STATE_ACTIVATED)) {
		signalling = TRUE;
	}

	_LOGD ("check-master-ready: %s (state %s, %s)",
	       signalling
	           ? "signal"
	           : (priv->master_ready ? "already signalled" : "not signalling"),
	       state_to_string (priv->state),
	       priv->master
	           ? nm_sprintf_bufa (128, "master %p is in state %s",
	                              priv->master,
	                              state_to_string (nm_active_connection_get_state (priv->master)))
	           : "no master");

	if (signalling) {
		priv->master_ready = TRUE;
		_notify (self, PROP_INT_MASTER_READY);

		/* Also notify clients to recheck the exported 'master' property to
		 * ensure that if the master connection was created without a device
		 * that we notify clients when the master device is known.
		 */
		_notify (self, PROP_MASTER);
	}
}

static void
master_state_cb (NMActiveConnection *master,
                 GParamSpec *pspec,
                 gpointer user_data)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (user_data);
	NMActiveConnectionState master_state = nm_active_connection_get_state (master);
	NMDevice *master_device = nm_active_connection_get_device (master);

	check_master_ready (self);

	if (   master_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATING
	    && (!master_device || !nm_device_is_real (master_device))) {
		/* Master failed without ever creating or realizing its device */
		if (NM_ACTIVE_CONNECTION_GET_CLASS (self)->master_failed)
			NM_ACTIVE_CONNECTION_GET_CLASS (self)->master_failed (self);
	}
}

/**
 * nm_active_connection_set_master:
 * @self: the #NMActiveConnection
 * @master: if the activation depends on another device (ie, bond or bridge
 * master to which this device will be enslaved) pass the #NMActiveConnection
 * that this activation request is a child of
 *
 * Sets the master active connection of @self.
 */
void
nm_active_connection_set_master (NMActiveConnection *self, NMActiveConnection *master)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));
	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (master));

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	/* Master is write-once, and must be set before exporting the object */
	g_return_if_fail (priv->master == NULL);
	g_return_if_fail (!nm_exported_object_is_exported (NM_EXPORTED_OBJECT (self)));
	if (priv->device) {
		/* Note, the master ActiveConnection may not yet have a device */
		g_return_if_fail (priv->device != nm_active_connection_get_device (master));
	}

	_LOGD ("set master %p, %s, state %s",
	       master,
	       nm_active_connection_get_settings_connection_id (master),
	       state_to_string (nm_active_connection_get_state (master)));

	priv->master = g_object_ref (master);
	g_signal_connect (priv->master,
	                  "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  (GCallback) master_state_cb,
	                  self);

	check_master_ready (self);
}

NMActivationType
nm_active_connection_get_activation_type (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NM_ACTIVATION_TYPE_MANAGED);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->activation_type;
}

static void
_set_activation_type (NMActiveConnection *self,
                      NMActivationType activation_type)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (priv->activation_type == activation_type)
		return;

	priv->activation_type = activation_type;

	if (priv->settings_connection) {
		if (activation_type == NM_ACTIVATION_TYPE_EXTERNAL)
			g_signal_connect (priv->settings_connection, "notify::"NM_SETTINGS_CONNECTION_FLAGS, (GCallback) _settings_connection_notify_flags, self);
		else
			g_signal_handlers_disconnect_by_func (priv->settings_connection, _settings_connection_notify_flags, self);
	}
}

static void
_set_activation_type_managed (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (priv->activation_type == NM_ACTIVATION_TYPE_MANAGED)
		return;

	_LOGD ("update activation type from %s to %s",
	       nm_activation_type_to_string (priv->activation_type),
	       nm_activation_type_to_string (NM_ACTIVATION_TYPE_MANAGED));

	_set_activation_type (self, NM_ACTIVATION_TYPE_MANAGED);

	if (   priv->device
	    && self == NM_ACTIVE_CONNECTION (nm_device_get_act_request (priv->device))
	    && NM_IN_SET (nm_device_sys_iface_state_get (priv->device),
	                  NM_DEVICE_SYS_IFACE_STATE_EXTERNAL,
	                  NM_DEVICE_SYS_IFACE_STATE_ASSUME))
		nm_device_sys_iface_state_set (priv->device, NM_DEVICE_SYS_IFACE_STATE_MANAGED);
}

/*****************************************************************************/

static void
_settings_connection_notify_flags (NMSettingsConnection *settings_connection,
                                   GParamSpec *param,
                                   NMActiveConnection *self)
{
	GError *error = NULL;

	nm_assert (NM_IS_ACTIVE_CONNECTION (self));
	nm_assert (NM_IS_SETTINGS_CONNECTION (settings_connection));
	nm_assert (nm_active_connection_get_activation_type (self) == NM_ACTIVATION_TYPE_EXTERNAL);
	nm_assert (NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->settings_connection == settings_connection);

	if (NM_FLAGS_HAS (nm_settings_connection_get_flags (settings_connection),
	                  NM_SETTINGS_CONNECTION_FLAGS_NM_GENERATED))
		return;

	_set_activation_type_managed (self);
	if (!nm_device_reapply (nm_active_connection_get_device (self),
	                        NM_CONNECTION (nm_active_connection_get_settings_connection (self)),
	                        &error)) {
		_LOGW ("failed to reapply new device settings on previously externally managed device: %s",
		       error->message);
		g_error_free (error);
	}
}

/*****************************************************************************/

static void unwatch_parent (NMActiveConnection *self, gboolean unref);

static void
parent_destroyed (gpointer user_data, GObject *parent)
{
	NMActiveConnection *self = user_data;

	unwatch_parent (self, FALSE);
	g_signal_emit (self, signals[PARENT_ACTIVE], 0, NULL);
}

static void
parent_state_cb (NMActiveConnection *parent_ac,
                 GParamSpec *pspec,
                 gpointer user_data)
{
	NMActiveConnection *self = user_data;
	NMActiveConnectionState parent_state = nm_active_connection_get_state (parent_ac);

	if (parent_state < NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		return;

	unwatch_parent (self, TRUE);
	g_signal_emit (self, signals[PARENT_ACTIVE], 0, parent_ac);
}

static void
unwatch_parent (NMActiveConnection *self, gboolean unref)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	g_signal_handlers_disconnect_by_func (priv->parent,
	                                      (GCallback) parent_state_cb,
	                                      self);
	if (unref)
		g_object_weak_unref ((GObject *) priv->parent, parent_destroyed, self);
	priv->parent = NULL;
}

/**
 * nm_active_connection_set_parent:
 * @self: the #NMActiveConnection
 * @parent: The #NMActiveConnection that must be active before the manager
 * can proceed progressing the device to disconnected state for us.
 *
 * Sets the parent connection of @self. A "parent-active" signal will be
 * emitted when the parent connection becomes active.
 */
void
nm_active_connection_set_parent (NMActiveConnection *self, NMActiveConnection *parent)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	g_return_if_fail (priv->parent == NULL);
	priv->parent = parent;
	g_signal_connect (priv->parent,
	                  "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  (GCallback) parent_state_cb,
	                  self);
	g_object_weak_ref ((GObject *) priv->parent, parent_destroyed, self);
}

/*****************************************************************************/

static void
auth_done (NMAuthChain *chain,
           GError *error,
           GDBusMethodInvocation *unused,
           gpointer user_data)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (user_data);
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	NMAuthCallResult result;

	g_assert (priv->chain == chain);
	g_assert (priv->result_func != NULL);

	/* Must stay alive over the callback */
	g_object_ref (self);

	if (error) {
		priv->result_func (self, FALSE, error->message, priv->user_data1, priv->user_data2);
		goto done;
	}

	/* Caller has had a chance to obtain authorization, so we only need to
	 * check for 'yes' here.
	 */
	result = nm_auth_chain_get_result (chain, NM_AUTH_PERMISSION_NETWORK_CONTROL);
	if (result != NM_AUTH_CALL_RESULT_YES) {
		priv->result_func (self,
		                   FALSE,
		                   "Not authorized to control networking.",
		                   priv->user_data1,
		                   priv->user_data2);
		goto done;
	}

	if (priv->wifi_shared_permission) {
		result = nm_auth_chain_get_result (chain, priv->wifi_shared_permission);
		if (result != NM_AUTH_CALL_RESULT_YES) {
			priv->result_func (self,
			                   FALSE,
			                   "Not authorized to share connections via wifi.",
			                   priv->user_data1,
			                   priv->user_data2);
			goto done;
		}
	}

	/* Otherwise authorized and available to activate */
	priv->result_func (self, TRUE, NULL, priv->user_data1, priv->user_data2);

done:
	nm_auth_chain_unref (chain);
	priv->chain = NULL;
	priv->result_func = NULL;
	priv->user_data1 = NULL;
	priv->user_data2 = NULL;

	g_object_unref (self);
}

/**
 * nm_active_connection_authorize:
 * @self: the #NMActiveConnection
 * @initial_connection: (allow-none): for add-and-activate, there
 *   is no @settings_connection available when creating the active connection.
 *   Instead pass an alternative connection.
 * @result_func: function to be called on success or error
 * @user_data1: pointer passed to @result_func
 * @user_data2: additional pointer passed to @result_func
 *
 * Checks whether the subject that initiated the active connection (read from
 * the #NMActiveConnection::subject property) is authorized to complete this
 * activation request.
 */
void
nm_active_connection_authorize (NMActiveConnection *self,
                                NMConnection *initial_connection,
                                NMActiveConnectionAuthResultFunc result_func,
                                gpointer user_data1,
                                gpointer user_data2)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	const char *wifi_permission = NULL;
	NMConnection *con;

	g_return_if_fail (result_func != NULL);
	g_return_if_fail (priv->chain == NULL);

	if (initial_connection) {
		g_return_if_fail (NM_IS_CONNECTION (initial_connection));
		g_return_if_fail (!priv->settings_connection);
		g_return_if_fail (!priv->applied_connection);
		con = initial_connection;
	} else {
		g_return_if_fail (NM_IS_SETTINGS_CONNECTION (priv->settings_connection));
		g_return_if_fail (NM_IS_CONNECTION (priv->applied_connection));
		con = priv->applied_connection;
	}

	priv->chain = nm_auth_chain_new_subject (priv->subject, NULL, auth_done, self);
	g_assert (priv->chain);

	/* Check that the subject is allowed to use networking at all */
	nm_auth_chain_add_call (priv->chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);

	/* Shared wifi connections require special permissions too */
	wifi_permission = nm_utils_get_shared_wifi_permission (con);
	if (wifi_permission) {
		priv->wifi_shared_permission = wifi_permission;
		nm_auth_chain_add_call (priv->chain, wifi_permission, TRUE);
	}

	/* Wait for authorization */
	priv->result_func = result_func;
	priv->user_data1 = user_data1;
	priv->user_data2 = user_data2;
}

/*****************************************************************************/

static guint64
_version_id_new (void)
{
	static guint64 id = 0;

	return ++id;
}

guint64
nm_active_connection_version_id_get (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), 0);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->version_id;
}

guint64
nm_active_connection_version_id_bump (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), 0);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE  (self);
	priv->version_id = _version_id_new ();
	_LOGT ("new version-id %llu", (unsigned long long) priv->version_id);
	return priv->version_id;
}

/*****************************************************************************/

static void
_device_cleanup (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (priv->device) {
		g_signal_handlers_disconnect_by_func (priv->device, G_CALLBACK (device_state_changed), self);
		g_signal_handlers_disconnect_by_func (priv->device, G_CALLBACK (device_master_changed), self);
		g_signal_handlers_disconnect_by_func (priv->device, G_CALLBACK (device_metered_changed), self);
	}

	if (priv->pending_activation_id) {
		nm_device_remove_pending_action (priv->device, priv->pending_activation_id, TRUE);
		g_clear_pointer (&priv->pending_activation_id, g_free);
	}

	g_clear_object (&priv->device);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE ((NMActiveConnection *) object);
	GPtrArray *devices;
	NMDevice *master_device = NULL;

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_string (value, nm_connection_get_path (NM_CONNECTION (priv->settings_connection)));
		break;
	case PROP_ID:
		g_value_set_string (value, nm_connection_get_id (NM_CONNECTION (priv->settings_connection)));
		break;
	case PROP_UUID:
		g_value_set_string (value, nm_connection_get_uuid (NM_CONNECTION (priv->settings_connection)));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_connection_get_connection_type (NM_CONNECTION (priv->settings_connection)));
		break;
	case PROP_SPECIFIC_OBJECT:
		g_value_set_string (value, priv->specific_object ? priv->specific_object : "/");
		break;
	case PROP_DEVICES:
		devices = g_ptr_array_sized_new (2);
		if (priv->device && priv->state < NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
			g_ptr_array_add (devices, g_strdup (nm_exported_object_get_path (NM_EXPORTED_OBJECT (priv->device))));
		g_ptr_array_add (devices, NULL);
		g_value_take_boxed (value, (char **) g_ptr_array_free (devices, FALSE));
		break;
	case PROP_STATE:
		if (priv->state_set)
			g_value_set_uint (value, priv->state);
		else {
			/* When the AC has just been created, its externally-visible state should
			 * be "ACTIVATING", even though internally it is "UNKNOWN".
			 */
			g_value_set_uint (value, NM_ACTIVE_CONNECTION_STATE_ACTIVATING);
		}
		break;
	case PROP_STATE_FLAGS:
		g_value_set_uint (value, priv->state_flags);
		break;
	case PROP_DEFAULT:
		g_value_set_boolean (value, priv->is_default);
		break;
	case PROP_IP4_CONFIG:
		/* The IP and DHCP config properties may be overridden by a subclass */
		g_value_set_string (value, "/");
		break;
	case PROP_DHCP4_CONFIG:
		g_value_set_string (value, "/");
		break;
	case PROP_DEFAULT6:
		g_value_set_boolean (value, priv->is_default6);
		break;
	case PROP_IP6_CONFIG:
		g_value_set_string (value, "/");
		break;
	case PROP_DHCP6_CONFIG:
		g_value_set_string (value, "/");
		break;
	case PROP_VPN:
		g_value_set_boolean (value, priv->vpn);
		break;
	case PROP_MASTER:
		if (priv->master)
			master_device = nm_active_connection_get_device (priv->master);
		nm_utils_g_value_set_object_path (value, master_device);
		break;
	case PROP_INT_SUBJECT:
		g_value_set_object (value, priv->subject);
		break;
	case PROP_INT_MASTER_READY:
		g_value_set_boolean (value, priv->master_ready);
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
	NMActiveConnection *self = (NMActiveConnection *) object;
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	const char *tmp;
	NMSettingsConnection *con;
	NMConnection *acon;
	int i;

	switch (prop_id) {
	case PROP_INT_SETTINGS_CONNECTION:
		/* construct-only */
		con = g_value_get_object (value);
		if (con)
			_set_settings_connection (self, con);
		break;
	case PROP_INT_APPLIED_CONNECTION:
		/* construct-only */
		acon = g_value_get_object (value);
		if (acon) {
			/* we don't call _set_applied_connection_take() yet, because the instance
			 * is not yet fully initialized. We are currently in the process of setting
			 * the constructor properties.
			 *
			 * For now, just piggyback the connection, but call _set_applied_connection_take()
			 * in constructed(). */
			priv->applied_connection = g_object_ref (acon);
		}
		break;
	case PROP_INT_DEVICE:
		/* construct-only */
		nm_active_connection_set_device (self, g_value_get_object (value));
		break;
	case PROP_INT_SUBJECT:
		/* construct-only */
		priv->subject = g_value_dup_object (value);
		break;
	case PROP_INT_MASTER:
		nm_active_connection_set_master (self, g_value_get_object (value));
		break;
	case PROP_INT_ACTIVATION_TYPE:
		/* construct-only */
		i = g_value_get_int (value);
		if (!NM_IN_SET (i, NM_ACTIVATION_TYPE_MANAGED,
		                   NM_ACTIVATION_TYPE_ASSUME,
		                   NM_ACTIVATION_TYPE_EXTERNAL))
			g_return_if_reached ();
		_set_activation_type (self, (NMActivationType) i);
		break;
	case PROP_SPECIFIC_OBJECT:
		/* construct-only */
		tmp = g_value_get_string (value);
		/* NM uses "/" to mean NULL */
		if (g_strcmp0 (tmp, "/") != 0)
			priv->specific_object = g_strdup (tmp);
		break;
	case PROP_DEFAULT:
		priv->is_default = g_value_get_boolean (value);
		break;
	case PROP_DEFAULT6:
		priv->is_default6 = g_value_get_boolean (value);
		break;
	case PROP_VPN:
		/* construct-only */
		priv->vpn = g_value_get_boolean (value);
		break;
	case PROP_MASTER:
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_active_connection_init (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionPrivate);
	self->_priv = priv;

	c_list_init (&self->active_connections_lst);

	_LOGT ("creating");

	priv->activation_type = NM_ACTIVATION_TYPE_MANAGED;
	priv->version_id = _version_id_new ();
}

static void
constructed (GObject *object)
{
	NMActiveConnection *self = (NMActiveConnection *) object;
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->constructed (object);

	if (   !priv->applied_connection
	    && priv->settings_connection)
		priv->applied_connection = nm_simple_connection_new_clone (NM_CONNECTION (priv->settings_connection));

	_LOGD ("constructed (%s, version-id %llu, type %s)",
	       G_OBJECT_TYPE_NAME (self),
	       (unsigned long long) priv->version_id,
	       nm_activation_type_to_string (priv->activation_type));

	if (priv->applied_connection) {
		/* priv->applied_connection was set during the construction of the object.
		 * It's not yet fully initialized, so do that now.
		 *
		 * We delayed that, because we may log in _set_applied_connection_take(), and the
		 * first logging line should be "constructed" above). */
		_set_applied_connection_take (self,
		                              g_steal_pointer (&priv->applied_connection));
	}

	g_return_if_fail (priv->subject);
}

static void
dispose (GObject *object)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (object);
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	nm_assert (!c_list_is_linked (&self->active_connections_lst));

	_LOGD ("disposing");

	if (priv->chain) {
		nm_auth_chain_unref (priv->chain);
		priv->chain = NULL;
	}

	g_free (priv->specific_object);
	priv->specific_object = NULL;

	_set_settings_connection (self, NULL);
	g_clear_object (&priv->applied_connection);

	_device_cleanup (self);

	if (priv->master) {
		g_signal_handlers_disconnect_by_func (priv->master,
		                                      (GCallback) master_state_cb,
		                                      self);
	}
	g_clear_object (&priv->master);

	if (priv->parent)
		unwatch_parent (self, TRUE);

	g_clear_object (&priv->subject);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
}

static void
nm_active_connection_class_init (NMActiveConnectionClass *ac_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ac_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (ac_class);

	g_type_class_add_private (ac_class, sizeof (NMActiveConnectionPrivate));

	exported_object_class->export_path = NM_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/ActiveConnection");

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	/* D-Bus exported properties */
	obj_properties[PROP_CONNECTION] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_CONNECTION, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ID] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_ID, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_UUID] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_UUID, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_TYPE] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_TYPE, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SPECIFIC_OBJECT] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DEVICES] =
	     g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STATE] =
	     g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE, "", "",
	                        NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
	                        NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
	                        NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STATE_FLAGS] =
	     g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE_FLAGS, "", "",
	                        0, G_MAXUINT32, NM_ACTIVATION_STATE_FLAG_NONE,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DEFAULT] =
	     g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IP4_CONFIG] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_IP4_CONFIG, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DHCP4_CONFIG] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_DHCP4_CONFIG, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DEFAULT6] =
	     g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT6, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IP6_CONFIG] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_IP6_CONFIG, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DHCP6_CONFIG] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_DHCP6_CONFIG, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_VPN] =
	     g_param_spec_boolean (NM_ACTIVE_CONNECTION_VPN, "", "",
	                           FALSE,
	                           G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_MASTER] =
	     g_param_spec_string (NM_ACTIVE_CONNECTION_MASTER, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/* Internal properties */
	obj_properties[PROP_INT_SETTINGS_CONNECTION] =
	     g_param_spec_object (NM_ACTIVE_CONNECTION_INT_SETTINGS_CONNECTION, "", "",
	                          NM_TYPE_SETTINGS_CONNECTION,
	                          G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INT_APPLIED_CONNECTION] =
	     g_param_spec_object (NM_ACTIVE_CONNECTION_INT_APPLIED_CONNECTION, "", "",
	                          NM_TYPE_CONNECTION,
	                          G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INT_DEVICE] =
	     g_param_spec_object (NM_ACTIVE_CONNECTION_INT_DEVICE, "", "",
	                          NM_TYPE_DEVICE,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INT_SUBJECT] =
	     g_param_spec_object (NM_ACTIVE_CONNECTION_INT_SUBJECT, "", "",
	                          NM_TYPE_AUTH_SUBJECT,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INT_MASTER] =
	     g_param_spec_object (NM_ACTIVE_CONNECTION_INT_MASTER, "", "",
	                          NM_TYPE_ACTIVE_CONNECTION,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INT_MASTER_READY] =
	     g_param_spec_boolean (NM_ACTIVE_CONNECTION_INT_MASTER_READY, "", "",
	                           FALSE, G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INT_ACTIVATION_TYPE] =
	     g_param_spec_int (NM_ACTIVE_CONNECTION_INT_ACTIVATION_TYPE, "", "",
	                       NM_ACTIVATION_TYPE_MANAGED,
	                       NM_ACTIVATION_TYPE_EXTERNAL,
	                       NM_ACTIVATION_TYPE_MANAGED,
	                       G_PARAM_WRITABLE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[DEVICE_CHANGED] =
	    g_signal_new (NM_ACTIVE_CONNECTION_DEVICE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMActiveConnectionClass, device_changed),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, NM_TYPE_DEVICE, NM_TYPE_DEVICE);

	signals[DEVICE_METERED_CHANGED] =
	    g_signal_new (NM_ACTIVE_CONNECTION_DEVICE_METERED_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMActiveConnectionClass, device_metered_changed),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[PARENT_ACTIVE] =
	    g_signal_new (NM_ACTIVE_CONNECTION_PARENT_ACTIVE,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMActiveConnectionClass, parent_active),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_ACTIVE_CONNECTION);

	signals[STATE_CHANGED] =
	    g_signal_new (NM_ACTIVE_CONNECTION_STATE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (ac_class),
	                                        NMDBUS_TYPE_ACTIVE_CONNECTION_SKELETON,
	                                        NULL);
}

