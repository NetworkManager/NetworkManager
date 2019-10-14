// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-act-request.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "c-list/src/c-list.h"

#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "devices/nm-device.h"
#include "nm-active-connection.h"
#include "settings/nm-settings-connection.h"
#include "nm-auth-subject.h"

typedef struct {
	char *table;
	char *rule;
} ShareRule;

typedef struct {
	CList call_ids_lst_head;
	gboolean shared;
	GSList *share_rules;
} NMActRequestPrivate;

struct _NMActRequest {
	NMActiveConnection parent;
	NMActRequestPrivate _priv;
};

typedef struct {
	NMActiveConnectionClass parent;
} NMActRequestClass;

enum {
	PROP_0,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,

	LAST_PROP
};

G_DEFINE_TYPE (NMActRequest, nm_act_request, NM_TYPE_ACTIVE_CONNECTION)

#define NM_ACT_REQUEST_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMActRequest, NM_IS_ACT_REQUEST)

/*****************************************************************************/

NMSettingsConnection *
nm_act_request_get_settings_connection (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return nm_active_connection_get_settings_connection (NM_ACTIVE_CONNECTION (req));
}

NMConnection *
nm_act_request_get_applied_connection (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return nm_active_connection_get_applied_connection (NM_ACTIVE_CONNECTION (req));
}

/*****************************************************************************/

struct _NMActRequestGetSecretsCallId {
	CList call_ids_lst;
	NMActRequest *self;
	NMActRequestSecretsFunc callback;
	gpointer callback_data;
	NMSettingsConnectionCallId *call_id;
	bool has_ref;
};

static void
_get_secrets_call_id_free (NMActRequestGetSecretsCallId *call_id)
{
	nm_assert (call_id);
	nm_assert (!c_list_is_linked (&call_id->call_ids_lst));

	if (call_id->has_ref)
		g_object_unref (call_id->self);
	g_slice_free (NMActRequestGetSecretsCallId, call_id);
}

static void
get_secrets_cb (NMSettingsConnection *connection,
                NMSettingsConnectionCallId *call_id_s,
                const char *agent_username,
                const char *setting_name,
                GError *error,
                gpointer user_data)
{
	NMActRequestGetSecretsCallId *call_id = user_data;
	NMActRequestPrivate *priv;

	g_return_if_fail (call_id && call_id->call_id == call_id_s);
	g_return_if_fail (NM_IS_ACT_REQUEST (call_id->self));

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	priv = NM_ACT_REQUEST_GET_PRIVATE (call_id->self);

	nm_assert (c_list_contains (&priv->call_ids_lst_head, &call_id->call_ids_lst));

	c_list_unlink (&call_id->call_ids_lst);

	if (call_id->callback)
		call_id->callback (call_id->self, call_id, connection, error, call_id->callback_data);

	_get_secrets_call_id_free (call_id);
}

/**
 * nm_act_request_get_secrets:
 * @self:
 * @ref_self: if %TRUE, the pending call take a reference on @self.
 *   It also allows you to omit the @self argument in nm_act_request_cancel_secrets().
 * @setting_name:
 * @flags:
 * @hint:
 * @callback:
 * @callback_data:
 *
 * Asnychronously starts the request for secrets. This function cannot
 * fail.
 *
 * The return call-id can be used to cancel the request. You are
 * only allowed to cancel a still pending operation (once).
 * The callback will always be invoked once, even for canceling
 * or disposing of NMActRequest.
 *
 * Returns: a call-id.
 */
NMActRequestGetSecretsCallId *
nm_act_request_get_secrets (NMActRequest *self,
                            gboolean ref_self,
                            const char *setting_name,
                            NMSecretAgentGetSecretsFlags flags,
                            const char *const*hints,
                            NMActRequestSecretsFunc callback,
                            gpointer callback_data)
{
	NMActRequestPrivate *priv;
	NMActRequestGetSecretsCallId *call_id;
	NMSettingsConnectionCallId *call_id_s;
	NMSettingsConnection *settings_connection;
	NMConnection *applied_connection;

	g_return_val_if_fail (NM_IS_ACT_REQUEST (self), NULL);

	priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	settings_connection = nm_act_request_get_settings_connection (self);
	applied_connection = nm_act_request_get_applied_connection (self);

	call_id = g_slice_new0 (NMActRequestGetSecretsCallId);
	call_id->has_ref = ref_self;
	call_id->self = ref_self ? g_object_ref (self) : self;
	call_id->callback = callback;
	call_id->callback_data = callback_data;
	c_list_link_tail (&priv->call_ids_lst_head, &call_id->call_ids_lst);

	if (nm_active_connection_get_user_requested (NM_ACTIVE_CONNECTION (self)))
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED;

	call_id_s = nm_settings_connection_get_secrets (settings_connection,
	                                                applied_connection,
	                                                nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (self)),
	                                                setting_name,
	                                                flags,
	                                                hints,
	                                                get_secrets_cb,
	                                                call_id);
	call_id->call_id = call_id_s;
	g_return_val_if_fail (call_id_s, NULL);
	return call_id;
}

static void
_do_cancel_secrets (NMActRequest *self, NMActRequestGetSecretsCallId *call_id, gboolean is_disposing)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	nm_assert (call_id && call_id->self == self);
	nm_assert (c_list_contains (&priv->call_ids_lst_head, &call_id->call_ids_lst));

	c_list_unlink (&call_id->call_ids_lst);

	nm_settings_connection_cancel_secrets (nm_act_request_get_settings_connection (self), call_id->call_id);

	if (call_id->callback) {
		gs_free_error GError *error = NULL;

		nm_utils_error_set_cancelled (&error, is_disposing, "NMActRequest");
		call_id->callback (self, call_id, NULL, error, call_id->callback_data);
	}

	_get_secrets_call_id_free (call_id);
}

/**
 * nm_act_request_cancel_secrets:
 * @self: The #NMActRequest. Note that this argument can be %NULL if, and only if
 *   the call_id was created with @take_ref.
 * @call_id:
 *
 * You are only allowed to cancel the call once, and only before the callback
 * is already invoked. Note that cancelling causes the callback to be invoked
 * synchronously.
 */
void
nm_act_request_cancel_secrets (NMActRequest *self, NMActRequestGetSecretsCallId *call_id)
{
	g_return_if_fail (call_id);

	if (self) {
		g_return_if_fail (NM_IS_ACT_REQUEST (self));
		g_return_if_fail (self == call_id->self);
	} else {
		g_return_if_fail (call_id->has_ref);
		g_return_if_fail (NM_IS_ACT_REQUEST (call_id->self));
		self = call_id->self;
	}

	if (!c_list_is_linked (&call_id->call_ids_lst))
		g_return_if_reached ();

	_do_cancel_secrets (self, call_id, FALSE);
}

void
nm_act_request_clear_secrets (NMActRequest *self)
{
	g_return_if_fail (NM_IS_ACT_REQUEST (self));

	nm_active_connection_clear_secrets ((NMActiveConnection *) self);
}

/*****************************************************************************/

static void
clear_share_rules (NMActRequest *req)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (req);
	GSList *iter;

	for (iter = priv->share_rules; iter; iter = g_slist_next (iter)) {
		ShareRule *rule = (ShareRule *) iter->data;

		g_free (rule->table);
		g_free (rule->rule);
		g_free (rule);
	}

	g_slist_free (priv->share_rules);
	priv->share_rules = NULL;
}

void
nm_act_request_set_shared (NMActRequest *req, gboolean shared)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (req);
	GSList *list, *iter;

	g_return_if_fail (NM_IS_ACT_REQUEST (req));

	NM_ACT_REQUEST_GET_PRIVATE (req)->shared = shared;

	/* Tear the rules down in reverse order when sharing is stopped */
	list = g_slist_copy (priv->share_rules);
	if (!shared)
		list = g_slist_reverse (list);

	/* Send the rules to iptables */
	for (iter = list; iter; iter = g_slist_next (iter)) {
		ShareRule *rule = (ShareRule *) iter->data;
		char *envp[1] = { NULL };
		gs_strfreev char **argv = NULL;
		gs_free char *cmd = NULL;

		cmd = g_strdup_printf ("%s --table %s %s %s",
		                       IPTABLES_PATH,
		                       rule->table,
		                       shared ? "--insert" : "--delete",
		                       rule->rule);
		if (!cmd)
			continue;

		argv = g_strsplit (cmd, " ", 0);
		if (argv && argv[0]) {
			int status;
			GError *error = NULL;

			nm_log_info (LOGD_SHARING, "Executing: %s", cmd);
			if (!g_spawn_sync ("/", argv, envp, G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
			                   NULL, NULL, NULL, NULL, &status, &error)) {
				nm_log_warn (LOGD_SHARING, "Error executing command: %s",
				             error->message);
				g_clear_error (&error);
			} else if (WEXITSTATUS (status)) {
				nm_log_warn (LOGD_SHARING, "** Command returned exit status %d.",
				             WEXITSTATUS (status));
			}
		}
	}

	g_slist_free (list);

	/* Clear the share rule list when sharing is stopped */
	if (!shared)
		clear_share_rules (req);
}

gboolean
nm_act_request_get_shared (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->shared;
}

void
nm_act_request_add_share_rule (NMActRequest *req,
                               const char *table,
                               const char *table_rule)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (req);
	ShareRule *rule;

	g_return_if_fail (NM_IS_ACT_REQUEST (req));
	g_return_if_fail (table != NULL);
	g_return_if_fail (table_rule != NULL);

	rule = g_malloc0 (sizeof (ShareRule));
	rule->table = g_strdup (table);
	rule->rule = g_strdup (table_rule);
	priv->share_rules = g_slist_prepend (priv->share_rules, rule);
}

/*****************************************************************************/

static void
device_notify (GObject    *object,
               GParamSpec *pspec,
               gpointer    self)
{
	g_object_notify (self, pspec->name);
}

static void
device_state_changed (NMActiveConnection *active,
                      NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state)
{
	NMActiveConnectionState cur_ac_state = nm_active_connection_get_state (active);
	NMActiveConnectionState ac_state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
	NMActiveConnectionStateReason ac_state_reason = NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN;

	/* Decide which device state changes to handle when this active connection
	 * is not the device's current request.  Two cases here: (a) the AC is
	 * pending and not yet active, and (b) the AC was active but the device is
	 * entering DISCONNECTED state (which clears the device's current AC before
	 * emitting the state change signal).
	 */
	if (NM_ACTIVE_CONNECTION (nm_device_get_act_request (device)) != active) {
		/* Some other request is activating; this one must be pending */
		if (new_state >= NM_DEVICE_STATE_PREPARE)
			return;
		else if (new_state == NM_DEVICE_STATE_DISCONNECTED) {
			/* This request hasn't started activating yet; the device is
			 * disconnecting and cleaning up a previous activation request.
			 */
			if (cur_ac_state < NM_ACTIVE_CONNECTION_STATE_ACTIVATING)
				return;

			/* Catch device disconnections after this request has been active */
		}

		/* All states < DISCONNECTED are fatal and handled */
	}

	/* Set NMActiveConnection state based on the device's state */
	switch (new_state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
		ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATED;

		g_signal_connect (device, "notify::" NM_DEVICE_IP4_CONFIG,
		                  G_CALLBACK (device_notify), active);
		g_signal_connect (device, "notify::" NM_DEVICE_DHCP4_CONFIG,
		                  G_CALLBACK (device_notify), active);
		g_signal_connect (device, "notify::" NM_DEVICE_IP6_CONFIG,
		                  G_CALLBACK (device_notify), active);
		g_signal_connect (device, "notify::" NM_DEVICE_DHCP6_CONFIG,
		                  G_CALLBACK (device_notify), active);
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		ac_state = NM_ACTIVE_CONNECTION_STATE_DEACTIVATING;
		break;
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
		ac_state = NM_ACTIVE_CONNECTION_STATE_DEACTIVATED;
		ac_state_reason = NM_ACTIVE_CONNECTION_STATE_REASON_DEVICE_DISCONNECTED;

		g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_notify), active);
		break;
	default:
		break;
	}

	if (   ac_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
	    || ac_state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN)
		nm_active_connection_set_default (active, AF_UNSPEC, FALSE);

	nm_active_connection_set_state (active, ac_state, ac_state_reason);
}

static void
master_failed (NMActiveConnection *self)
{
	NMDevice *device;
	NMDeviceState device_state;

	/* If the connection has an active device, fail it */
	device = nm_active_connection_get_device (self);
	if (device) {
		device_state = nm_device_get_state (device);
		if (nm_device_is_activating (device) || (device_state == NM_DEVICE_STATE_ACTIVATED)) {
			nm_device_queue_state (device,
			                       NM_DEVICE_STATE_FAILED,
			                       NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED);
			return;
		}
	}

	/* If no device, or the device wasn't active, just move to deactivated state */
	nm_active_connection_set_state (self,
	                                NM_ACTIVE_CONNECTION_STATE_DEACTIVATED,
	                                NM_ACTIVE_CONNECTION_STATE_REASON_DEPENDENCY_FAILED);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMActiveConnection *active;
	NMDevice *device;
	char *name;

	switch (prop_id) {
	case PROP_IP4_CONFIG:
		name = NM_DEVICE_IP4_CONFIG;
		break;
	case PROP_DHCP4_CONFIG:
		name = NM_DEVICE_DHCP4_CONFIG;
		break;
	case PROP_IP6_CONFIG:
		name = NM_DEVICE_IP6_CONFIG;
		break;
	case PROP_DHCP6_CONFIG:
		name = NM_DEVICE_DHCP6_CONFIG;
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		return;
	}

	active = NM_ACTIVE_CONNECTION (object);
	device = nm_active_connection_get_device (active);
	if (   !device
	    || !NM_IN_SET (nm_active_connection_get_state (active),
	                   NM_ACTIVE_CONNECTION_STATE_ACTIVATED,
	                   NM_ACTIVE_CONNECTION_STATE_DEACTIVATING)) {
		g_value_set_string (value, NULL);
		return;
	}

	g_object_get_property (G_OBJECT (device), name, value);
}

static void
nm_act_request_init (NMActRequest *req)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (req);

	c_list_init (&priv->call_ids_lst_head);
}

/**
 * nm_act_request_new:
 *
 * @settings_connection: (allow-none): the connection to activate @device with
 * @applied_connection: (allow-none): the applied connection
 * @specific_object: the object path of the specific object (ie, Wi-Fi access point,
 *    etc) that will be used to activate @connection and @device
 * @subject: the #NMAuthSubject representing the requestor of the activation
 * @activation_type: the #NMActivationType
 * @activation_reason: the reason for activation
 * @initial_state_flags: the initial state flags.
 * @device: the device/interface to configure according to @connection
 *
 * Creates a new device-based activation request. If an applied connection is
 * supplied, it shall not be modified by the caller afterwards.
 *
 * Returns: the new activation request on success, %NULL on error.
 */
NMActRequest *
nm_act_request_new (NMSettingsConnection *settings_connection,
                    NMConnection *applied_connection,
                    const char *specific_object,
                    NMAuthSubject *subject,
                    NMActivationType activation_type,
                    NMActivationReason activation_reason,
                    NMActivationStateFlags initial_state_flags,
                    NMDevice *device)
{
	g_return_val_if_fail (!settings_connection || NM_IS_SETTINGS_CONNECTION (settings_connection), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);

	return (NMActRequest *) g_object_new (NM_TYPE_ACT_REQUEST,
	                                      NM_ACTIVE_CONNECTION_INT_APPLIED_CONNECTION, applied_connection,
	                                      NM_ACTIVE_CONNECTION_INT_SETTINGS_CONNECTION, settings_connection,
	                                      NM_ACTIVE_CONNECTION_INT_DEVICE, device,
	                                      NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, specific_object,
	                                      NM_ACTIVE_CONNECTION_INT_SUBJECT, subject,
	                                      NM_ACTIVE_CONNECTION_INT_ACTIVATION_TYPE, (int) activation_type,
	                                      NM_ACTIVE_CONNECTION_INT_ACTIVATION_REASON, (int) activation_reason,
	                                      NM_ACTIVE_CONNECTION_STATE_FLAGS, (guint) initial_state_flags,
	                                      NULL);
}

static void
dispose (GObject *object)
{
	NMActRequest *self = NM_ACT_REQUEST (object);
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (self);
	NMActRequestGetSecretsCallId *call_id, *call_id_safe;

	/* Kill any in-progress secrets requests */
	c_list_for_each_entry_safe (call_id, call_id_safe, &priv->call_ids_lst_head, call_ids_lst)
		_do_cancel_secrets (self, call_id, TRUE);

	/* Clear any share rules */
	if (priv->share_rules) {
		nm_act_request_set_shared (NM_ACT_REQUEST (object), FALSE);
		clear_share_rules (NM_ACT_REQUEST (object));
	}

	G_OBJECT_CLASS (nm_act_request_parent_class)->dispose (object);
}

static void
nm_act_request_class_init (NMActRequestClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);
	NMActiveConnectionClass *active_class = NM_ACTIVE_CONNECTION_CLASS (req_class);

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	active_class->master_failed = master_failed;
	active_class->device_state_changed = device_state_changed;

	/* properties */
	g_object_class_override_property (object_class, PROP_IP4_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP4_CONFIG);
	g_object_class_override_property (object_class, PROP_DHCP4_CONFIG,
	                                  NM_ACTIVE_CONNECTION_DHCP4_CONFIG);
	g_object_class_override_property (object_class, PROP_IP6_CONFIG,
	                                  NM_ACTIVE_CONNECTION_IP6_CONFIG);
	g_object_class_override_property (object_class, PROP_DHCP6_CONFIG,
	                                  NM_ACTIVE_CONNECTION_DHCP6_CONFIG);
}

