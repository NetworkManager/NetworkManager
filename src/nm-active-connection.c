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

#include "config.h"


#include "nm-glib.h"
#include "nm-types.h"
#include "nm-active-connection.h"
#include "nm-dbus-interface.h"
#include "nm-logging.h"
#include "nm-dbus-glib-types.h"
#include "nm-device.h"
#include "nm-settings-connection.h"
#include "nm-auth-utils.h"
#include "nm-auth-subject.h"
#include "NetworkManagerUtils.h"
#include "gsystem-local-alloc.h"
#include "nm-active-connection-glue.h"

/* Base class for anything implementing the Connection.Active D-Bus interface */
G_DEFINE_ABSTRACT_TYPE (NMActiveConnection, nm_active_connection, NM_TYPE_EXPORTED_OBJECT)

#define NM_ACTIVE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                             NM_TYPE_ACTIVE_CONNECTION, \
                                             NMActiveConnectionPrivate))

typedef struct {
	NMConnection *connection;
	char *specific_object;
	NMDevice *device;

	char *pending_activation_id;

	gboolean is_default;
	gboolean is_default6;
	NMActiveConnectionState state;
	gboolean state_set;
	gboolean vpn;

	NMAuthSubject *subject;
	NMActiveConnection *master;
	gboolean master_ready;

	gboolean assumed;

	NMAuthChain *chain;
	const char *wifi_shared_permission;
	NMActiveConnectionAuthResultFunc result_func;
	gpointer user_data1;
	gpointer user_data2;
} NMActiveConnectionPrivate;

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_ID,
	PROP_UUID,
	PROP_TYPE,
	PROP_SPECIFIC_OBJECT,
	PROP_DEVICES,
	PROP_STATE,
	PROP_DEFAULT,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_DEFAULT6,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,
	PROP_VPN,
	PROP_MASTER,

	PROP_INT_CONNECTION,
	PROP_INT_DEVICE,
	PROP_INT_SUBJECT,
	PROP_INT_MASTER,
	PROP_INT_MASTER_READY,

	LAST_PROP
};

enum {
	DEVICE_CHANGED,
	DEVICE_METERED_CHANGED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

static void check_master_ready (NMActiveConnection *self);
static void _device_cleanup (NMActiveConnection *self);

/****************************************************************/

static const char *
state_to_string (NMActiveConnectionState state)
{
	switch (state) {
	case NM_ACTIVE_CONNECTION_STATE_UNKNOWN:
		return "unknown";
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATING:
		return "activating";
	case NM_ACTIVE_CONNECTION_STATE_ACTIVATED:
		return "activated";
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATING:
		return "deactivating";
	case NM_ACTIVE_CONNECTION_STATE_DEACTIVATED:
		return "deactivated";
	}
	return "(none)";
}

NMActiveConnectionState
nm_active_connection_get_state (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->state;
}

void
nm_active_connection_set_state (NMActiveConnection *self,
                                NMActiveConnectionState new_state)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	NMActiveConnectionState old_state;

	if (priv->state == new_state)
		return;

	/* DEACTIVATED is a terminal state */
	if (priv->state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		g_return_if_fail (new_state != NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);

	old_state = priv->state;
	priv->state = new_state;
	priv->state_set = TRUE;
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_STATE);

	check_master_ready (self);

	if (   new_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    || old_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		nm_settings_connection_update_timestamp (NM_SETTINGS_CONNECTION (priv->connection),
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
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_IP4_CONFIG);
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DHCP4_CONFIG);
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_IP6_CONFIG);
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DHCP6_CONFIG);
	}

	if (priv->state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		/* Device is no longer relevant when deactivated. So remove it and
		 * emit property change notification so clients re-read the value,
		 * which will be NULL due to conditions in get_property().
		 */
		_device_cleanup (self);
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DEVICES);
	}
}

const char *
nm_active_connection_get_id (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return nm_connection_get_id (NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->connection);
}

const char *
nm_active_connection_get_uuid (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return nm_connection_get_uuid (NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->connection);
}

NMConnection *
nm_active_connection_get_connection (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->connection;
}

const char *
nm_active_connection_get_connection_type (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (priv->connection == NULL)
		return NULL;

	return nm_connection_get_connection_type (priv->connection);
}

void
nm_active_connection_set_connection (NMActiveConnection *self,
                                     NMConnection *connection)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	/* Can't change connection after the ActiveConnection is exported over D-Bus */
	g_return_if_fail (!nm_exported_object_is_exported (NM_EXPORTED_OBJECT (self)));
	g_return_if_fail (priv->connection == NULL || !NM_IS_SETTINGS_CONNECTION (priv->connection));

	if (priv->connection)
		g_object_unref (priv->connection);
	priv->connection = g_object_ref (connection);
}

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
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT);
}

void
nm_active_connection_set_default (NMActiveConnection *self, gboolean is_default)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));

	is_default = !!is_default;

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	if (priv->is_default == is_default)
		return;

	priv->is_default = is_default;
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DEFAULT);
}

gboolean
nm_active_connection_get_default (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->is_default;
}

void
nm_active_connection_set_default6 (NMActiveConnection *self, gboolean is_default6)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));

	is_default6 = !!is_default6;

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	if (priv->is_default6 == is_default6)
		return;

	priv->is_default6 = is_default6;
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DEFAULT6);
}

gboolean
nm_active_connection_get_default6 (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->is_default6;
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

	old_device = priv->device ? g_object_ref (priv->device) : NULL;
	_device_cleanup (self);

	if (device) {
		/* Device obviously can't be its own master */
		g_return_val_if_fail (!priv->master || device != nm_active_connection_get_device (priv->master), FALSE);

		priv->device = g_object_ref (device);

		g_signal_connect (device, "state-changed",
		                  G_CALLBACK (device_state_changed), self);
		g_signal_connect (device, "notify::master",
		                  G_CALLBACK (device_master_changed), self);
		g_signal_connect (device, "notify::" NM_DEVICE_METERED,
		                  G_CALLBACK (device_metered_changed), self);

		if (!priv->assumed) {
			priv->pending_activation_id = g_strdup_printf ("activation::%p", (void *)self);
			nm_device_add_pending_action (device, priv->pending_activation_id, TRUE);
		}
	} else
		priv->device = NULL;
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_INT_DEVICE);

	g_signal_emit (self, signals[DEVICE_CHANGED], 0, priv->device, old_device);

	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DEVICES);

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
	NMActiveConnectionState master_state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;

	if (priv->state != NM_ACTIVE_CONNECTION_STATE_ACTIVATING) {
		nm_log_dbg (LOGD_DEVICE, "(%p): not signalling master-ready (not activating)", self);
		return;
	}
	if (!priv->master) {
		nm_log_dbg (LOGD_DEVICE, "(%p): not signalling master-ready (no master)", self);
		return;
	}
	if (priv->master_ready) {
		nm_log_dbg (LOGD_DEVICE, "(%p): not signalling master-ready (already signaled)", self);
		return;
	}

	/* ActiveConnetions don't enter the ACTIVATING state until they have a
	 * NMDevice in PREPARE or higher states, so the master active connection's
	 * device will be ready to accept slaves when the master is in ACTIVATING
	 * or higher states.
	 */
	master_state = nm_active_connection_get_state (priv->master);
	nm_log_dbg (LOGD_DEVICE, "(%p): master ActiveConnection [%p] state now '%s' (%d)",
	            self, priv->master, state_to_string (master_state), master_state);

	if (   master_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING
	    || master_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		nm_log_dbg (LOGD_DEVICE, "(%p): signalling master-ready", self);

		priv->master_ready = TRUE;
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_INT_MASTER_READY);

		/* Also notify clients to recheck the exported 'master' property to
		 * ensure that if the master connection was created without a device
		 * that we notify clients when the master device is known.
		 */
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_MASTER);
	}
}

static void
master_state_cb (NMActiveConnection *master,
                 GParamSpec *pspec,
                 gpointer user_data)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (user_data);
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	NMActiveConnectionState master_state = nm_active_connection_get_state (master);

	check_master_ready (self);

	nm_log_dbg (LOGD_DEVICE, "(%p): master ActiveConnection [%p] state now '%s' (%d)",
	            self, master, state_to_string (master_state), master_state);

	if (   master_state >= NM_ACTIVE_CONNECTION_STATE_DEACTIVATING
	    && !priv->master_ready) {
		/* Master failed without ever creating its device */
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

	nm_log_dbg (LOGD_DEVICE, "(%p): master ActiveConnection is [%p] %s",
	            self, master, nm_active_connection_get_id (master));

	priv->master = g_object_ref (master);
	g_signal_connect (priv->master,
	                  "notify::" NM_ACTIVE_CONNECTION_STATE,
	                  (GCallback) master_state_cb,
	                  self);

	check_master_ready (self);
}

void
nm_active_connection_set_assumed (NMActiveConnection *self, gboolean assumed)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	g_return_if_fail (priv->assumed == FALSE);
	priv->assumed = assumed;

	if (priv->pending_activation_id) {
		nm_device_remove_pending_action (priv->device, priv->pending_activation_id, TRUE);
		g_clear_pointer (&priv->pending_activation_id, g_free);
	}
}

gboolean
nm_active_connection_get_assumed (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->assumed;
}

/****************************************************************/

static void
auth_done (NMAuthChain *chain,
           GError *error,
           DBusGMethodInvocation *unused,
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
                                NMActiveConnectionAuthResultFunc result_func,
                                gpointer user_data1,
                                gpointer user_data2)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	const char *wifi_permission = NULL;

	g_return_if_fail (result_func != NULL);
	g_return_if_fail (priv->chain == NULL);

	priv->chain = nm_auth_chain_new_subject (priv->subject, NULL, auth_done, self);
	g_assert (priv->chain);

	/* Check that the subject is allowed to use networking at all */
	nm_auth_chain_add_call (priv->chain, NM_AUTH_PERMISSION_NETWORK_CONTROL, TRUE);

	/* Shared wifi connections require special permissions too */
	wifi_permission = nm_utils_get_shared_wifi_permission (priv->connection);
	if (wifi_permission) {
		priv->wifi_shared_permission = wifi_permission;
		nm_auth_chain_add_call (priv->chain, wifi_permission, TRUE);
	}

	/* Wait for authorization */
	priv->result_func = result_func;
	priv->user_data1 = user_data1;
	priv->user_data2 = user_data2;
}

/****************************************************************/

static void
nm_active_connection_init (NMActiveConnection *self)
{
}

static void
constructed (GObject *object)
{
	G_OBJECT_CLASS (nm_active_connection_parent_class)->constructed (object);
	g_assert (NM_ACTIVE_CONNECTION_GET_PRIVATE (object)->subject);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);
	const char *tmp;

	switch (prop_id) {
	case PROP_INT_CONNECTION:
		g_warn_if_fail (priv->connection == NULL);
		priv->connection = g_value_dup_object (value);
		break;
	case PROP_INT_DEVICE:
		nm_active_connection_set_device (NM_ACTIVE_CONNECTION (object), g_value_get_object (value));
		break;
	case PROP_INT_SUBJECT:
		priv->subject = g_value_dup_object (value);
		break;
	case PROP_INT_MASTER:
		nm_active_connection_set_master (NM_ACTIVE_CONNECTION (object), g_value_get_object (value));
		break;
	case PROP_SPECIFIC_OBJECT:
		tmp = g_value_get_boxed (value);
		/* NM uses "/" to mean NULL */
		if (g_strcmp0 (tmp, "/") != 0)
			priv->specific_object = g_value_dup_boxed (value);
		break;
	case PROP_DEFAULT:
		priv->is_default = !!g_value_get_boolean (value);
		break;
	case PROP_DEFAULT6:
		priv->is_default6 = !!g_value_get_boolean (value);
		break;
	case PROP_VPN:
		priv->vpn = g_value_get_boolean (value);
		break;
	case PROP_MASTER:
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
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);
	GPtrArray *devices;
	NMDevice *master_device = NULL;

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_boxed (value, nm_connection_get_path (priv->connection));
		break;
	case PROP_ID:
		g_value_set_string (value, nm_connection_get_id (priv->connection));
		break;
	case PROP_UUID:
		g_value_set_string (value, nm_connection_get_uuid (priv->connection));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_connection_get_connection_type (priv->connection));
		break;
	case PROP_SPECIFIC_OBJECT:
		g_value_set_boxed (value, priv->specific_object ? priv->specific_object : "/");
		break;
	case PROP_DEVICES:
		devices = g_ptr_array_sized_new (1);
		if (priv->device && priv->state < NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
			g_ptr_array_add (devices, g_strdup (nm_exported_object_get_path (NM_EXPORTED_OBJECT (priv->device))));
		g_value_take_boxed (value, devices);
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
	case PROP_DEFAULT:
		g_value_set_boolean (value, priv->is_default);
		break;
	case PROP_IP4_CONFIG:
		/* The IP and DHCP config properties may be overridden by a subclass */
		g_value_set_boxed (value, "/");
		break;
	case PROP_DHCP4_CONFIG:
		g_value_set_boxed (value, "/");
		break;
	case PROP_DEFAULT6:
		g_value_set_boolean (value, priv->is_default6);
		break;
	case PROP_IP6_CONFIG:
		g_value_set_boxed (value, "/");
		break;
	case PROP_DHCP6_CONFIG:
		g_value_set_boxed (value, "/");
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

static void
dispose (GObject *object)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (object);
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (priv->chain) {
		nm_auth_chain_unref (priv->chain);
		priv->chain = NULL;
	}

	g_free (priv->specific_object);
	priv->specific_object = NULL;

	g_clear_object (&priv->connection);

	_device_cleanup (self);

	if (priv->master) {
		g_signal_handlers_disconnect_by_func (priv->master,
		                                      (GCallback) master_state_cb,
		                                      self);
	}
	g_clear_object (&priv->master);
	g_clear_object (&priv->subject);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
}

static void
nm_active_connection_class_init (NMActiveConnectionClass *ac_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ac_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (ac_class);

	g_type_class_add_private (ac_class, sizeof (NMActiveConnectionPrivate));

	exported_object_class->export_path = NM_DBUS_PATH "/ActiveConnection/%u";

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->constructed = constructed;
	object_class->dispose = dispose;

	/* D-Bus exported properties */
	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_CONNECTION, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_ID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_UUID,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_UUID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TYPE,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_TYPE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SPECIFIC_OBJECT,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES, "", "",
		                     DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE, "", "",
		                    NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
		                    NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
		                    NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DEFAULT,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IP4_CONFIG,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_IP4_CONFIG, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DHCP4_CONFIG,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_DHCP4_CONFIG, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DEFAULT6,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT6, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_IP6_CONFIG,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_IP6_CONFIG, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DHCP6_CONFIG,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_DHCP6_CONFIG, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_VPN,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_VPN, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MASTER,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_MASTER, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/* Internal properties */
	g_object_class_install_property
		(object_class, PROP_INT_CONNECTION,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_INT_CONNECTION, "", "",
		                      NM_TYPE_CONNECTION,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_INT_DEVICE,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_INT_DEVICE, "", "",
		                      NM_TYPE_DEVICE,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_INT_SUBJECT,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_INT_SUBJECT, "", "",
		                      NM_TYPE_AUTH_SUBJECT,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_INT_MASTER,
		 g_param_spec_object (NM_ACTIVE_CONNECTION_INT_MASTER, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_INT_MASTER_READY,
		 g_param_spec_boolean (NM_ACTIVE_CONNECTION_INT_MASTER_READY, "", "",
		                       FALSE, G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

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

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (ac_class),
	                                        &dbus_glib_nm_active_connection_object_info);
}

