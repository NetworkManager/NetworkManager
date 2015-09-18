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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>


#include "nm-activation-request.h"
#include "nm-default.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-device.h"
#include "nm-active-connection.h"
#include "nm-settings-connection.h"
#include "nm-auth-subject.h"

G_DEFINE_TYPE (NMActRequest, nm_act_request, NM_TYPE_ACTIVE_CONNECTION)

#define NM_ACT_REQUEST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                       NM_TYPE_ACT_REQUEST, \
                                       NMActRequestPrivate))

typedef struct {
	char *table;
	char *rule;
} ShareRule;

typedef struct {
	GSList *secrets_calls;
	gboolean shared;
	GSList *share_rules;
} NMActRequestPrivate;

enum {
	PROP_0,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,

	LAST_PROP
};

/*******************************************************************/

NMConnection *
nm_act_request_get_connection (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (req));
}

/*******************************************************************/

struct _NMActRequestGetSecretsCallId {
	NMActRequest *self;
	NMSettingsConnectionCallId call_id_s;
	NMActRequestSecretsFunc callback;
	gpointer callback_data;
};

typedef struct _NMActRequestGetSecretsCallId GetSecretsInfo;

static void
get_secrets_cb (NMSettingsConnection *connection,
                NMSettingsConnectionCallId call_id_s,
                const char *agent_username,
                const char *setting_name,
                GError *error,
                gpointer user_data)
{
	GetSecretsInfo *info = user_data;
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (info->self);

	g_return_if_fail (info->call_id_s == call_id_s);
	g_return_if_fail (g_slist_find (priv->secrets_calls, info));

	priv->secrets_calls = g_slist_remove (priv->secrets_calls, info);

	if (info->callback)
		info->callback (info->self, info, NM_CONNECTION (connection), error, info->callback_data);
	g_free (info);
}

/**
 * nm_act_request_get_secrets:
 * @self:
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
NMActRequestGetSecretsCallId
nm_act_request_get_secrets (NMActRequest *self,
                            const char *setting_name,
                            NMSecretAgentGetSecretsFlags flags,
                            const char *hint,
                            NMActRequestSecretsFunc callback,
                            gpointer callback_data)
{
	NMActRequestPrivate *priv;
	GetSecretsInfo *info;
	NMSettingsConnectionCallId call_id_s;
	NMConnection *connection;
	const char *hints[2] = { hint, NULL };

	g_return_val_if_fail (self, 0);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (self), 0);

	priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	info = g_malloc0 (sizeof (GetSecretsInfo));
	info->self = self;
	info->callback = callback;
	info->callback_data = callback_data;

	if (nm_active_connection_get_user_requested (NM_ACTIVE_CONNECTION (self)))
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_USER_REQUESTED;

	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (self));
	call_id_s = nm_settings_connection_get_secrets (NM_SETTINGS_CONNECTION (connection),
	                                                nm_active_connection_get_subject (NM_ACTIVE_CONNECTION (self)),
	                                                setting_name,
	                                                flags,
	                                                hints,
	                                                get_secrets_cb,
	                                                info,
	                                                NULL);
	if (call_id_s) {
		info->call_id_s = call_id_s;
		priv->secrets_calls = g_slist_append (priv->secrets_calls, info);
	} else
		g_free (info);

	return info;
}

void
nm_act_request_cancel_secrets (NMActRequest *self, NMActRequestGetSecretsCallId call_id)
{
	NMActRequestPrivate *priv;
	NMConnection *connection;

	g_return_if_fail (self);
	g_return_if_fail (NM_IS_ACT_REQUEST (self));
	g_return_if_fail (call_id);

	priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	if (g_slist_find (priv->secrets_calls, call_id))
		g_return_if_reached ();

	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (self));
	nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (connection), call_id->call_id_s);
}

/********************************************************************/

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
				nm_log_warn (LOGD_SHARING, "Error executing command: (%d) %s",
				             error ? error->code : -1,
				             (error && error->message) ? error->message : "(unknown)");
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
	priv->share_rules = g_slist_append (priv->share_rules, rule);
}

/********************************************************************/

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

		g_signal_handlers_disconnect_by_func (device, G_CALLBACK (device_notify), active);
		break;
	default:
		break;
	}

	if (   ac_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
	    || ac_state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN) {
		nm_active_connection_set_default (active, FALSE);
		nm_active_connection_set_default6 (active, FALSE);
	}

	nm_active_connection_set_state (active, ac_state);
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
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_DEPENDENCY_FAILED);
			return;
		}
	}

	/* If no device, or the device wasn't active, just move to deactivated state */
	nm_active_connection_set_state (self, NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);
}

/********************************************************************/

/**
 * nm_act_request_new:
 *
 * @connection: the connection to activate @device with
 * @specific_object: the object path of the specific object (ie, WiFi access point,
 *    etc) that will be used to activate @connection and @device
 * @subject: the #NMAuthSubject representing the requestor of the activation
 * @device: the device/interface to configure according to @connection; or %NULL
 * if the connection describes a software device which will be created during
 * connection activation
 *
 * Creates a new device-based activation request.
 *
 * Returns: the new activation request on success, %NULL on error.
 */
NMActRequest *
nm_act_request_new (NMConnection *connection,
                    const char *specific_object,
                    NMAuthSubject *subject,
                    NMDevice *device)
{
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!device || NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);

	return (NMActRequest *) g_object_new (NM_TYPE_ACT_REQUEST,
	                                      NM_ACTIVE_CONNECTION_INT_CONNECTION, connection,
	                                      NM_ACTIVE_CONNECTION_INT_DEVICE, device,
	                                      NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, specific_object,
	                                      NM_ACTIVE_CONNECTION_INT_SUBJECT, subject,
	                                      NULL);
}

static void
nm_act_request_init (NMActRequest *req)
{
}

static void
dispose (GObject *object)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);
	NMConnection *connection;

	/* Clear any share rules */
	if (priv->share_rules) {
		nm_act_request_set_shared (NM_ACT_REQUEST (object), FALSE);
		clear_share_rules (NM_ACT_REQUEST (object));
	}

	/* Kill any in-progress secrets requests */
	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (object));
	while (priv->secrets_calls) {
		GetSecretsInfo *info = priv->secrets_calls->data;

		nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (connection), info->call_id_s);

		g_return_if_fail (!priv->secrets_calls || info != priv->secrets_calls->data);
	}

	G_OBJECT_CLASS (nm_act_request_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDevice *device;

	device = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (object));
	if (!device) {
		g_value_set_string (value, "/");
		return;
	}

	switch (prop_id) {
	case PROP_IP4_CONFIG:
		g_object_get_property (G_OBJECT (device), NM_DEVICE_IP4_CONFIG, value);
		break;
	case PROP_DHCP4_CONFIG:
		g_object_get_property (G_OBJECT (device), NM_DEVICE_DHCP4_CONFIG, value);
		break;
	case PROP_IP6_CONFIG:
		g_object_get_property (G_OBJECT (device), NM_DEVICE_IP6_CONFIG, value);
		break;
	case PROP_DHCP6_CONFIG:
		g_object_get_property (G_OBJECT (device), NM_DEVICE_DHCP6_CONFIG, value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_act_request_class_init (NMActRequestClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);
	NMActiveConnectionClass *active_class = NM_ACTIVE_CONNECTION_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (NMActRequestPrivate));

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

