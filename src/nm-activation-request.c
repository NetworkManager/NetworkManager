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
#include <dbus/dbus-glib.h>

#include "nm-activation-request.h"
#include "nm-logging.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-device.h"
#include "nm-active-connection.h"
#include "nm-settings-connection.h"
#include "nm-posix-signals.h"


G_DEFINE_TYPE (NMActRequest, nm_act_request, NM_TYPE_ACTIVE_CONNECTION)

#define NM_ACT_REQUEST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                       NM_TYPE_ACT_REQUEST, \
                                       NMActRequestPrivate))

typedef struct {
	char *table;
	char *rule;
} ShareRule;

typedef struct {
	NMConnection *connection;
	NMDevice *device;
	guint device_state_id;
	char *dbus_sender;
	GSList *secrets_calls;
	gboolean shared;
	GSList *share_rules;
} NMActRequestPrivate;

/*******************************************************************/

NMConnection *
nm_act_request_get_connection (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (req));
}

const char *
nm_act_request_get_dbus_sender (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->dbus_sender;
}

/*******************************************************************/

typedef struct {
	NMActRequest *self;
	guint32 call_id;
	NMActRequestSecretsFunc callback;
	gpointer callback_data;
} GetSecretsInfo;

static void
get_secrets_cb (NMSettingsConnection *connection,
                guint32 call_id,
                const char *agent_username,
                const char *setting_name,
                GError *error,
                gpointer user_data)
{
	GetSecretsInfo *info = user_data;
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (info->self);

	g_return_if_fail (info->call_id == call_id);
	priv->secrets_calls = g_slist_remove (priv->secrets_calls, info);

	info->callback (info->self, call_id, NM_CONNECTION (connection), error, info->callback_data);
	g_free (info);
}

guint32
nm_act_request_get_secrets (NMActRequest *self,
                            const char *setting_name,
                            NMSettingsGetSecretsFlags flags,
                            const char *hint,
                            NMActRequestSecretsFunc callback,
                            gpointer callback_data)
{
	NMActRequestPrivate *priv;
	GetSecretsInfo *info;
	guint32 call_id;
	NMConnection *connection;
	gboolean user_requested;
	const char *hints[2] = { hint, NULL };

	g_return_val_if_fail (self, 0);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (self), 0);

	priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	info = g_malloc0 (sizeof (GetSecretsInfo));
	info->self = self;
	info->callback = callback;
	info->callback_data = callback_data;

	user_requested = nm_active_connection_get_user_requested (NM_ACTIVE_CONNECTION (self));
	if (user_requested)
		flags |= NM_SETTINGS_GET_SECRETS_FLAG_USER_REQUESTED;

	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (self));
	call_id = nm_settings_connection_get_secrets (NM_SETTINGS_CONNECTION (connection),
	                                              user_requested,
	                                              nm_active_connection_get_user_uid (NM_ACTIVE_CONNECTION (self)),
	                                              setting_name,
	                                              flags,
	                                              hints,
	                                              get_secrets_cb,
	                                              info,
	                                              NULL);
	if (call_id > 0) {
		info->call_id = call_id;
		priv->secrets_calls = g_slist_append (priv->secrets_calls, info);
	} else
		g_free (info);

	return call_id;
}

void
nm_act_request_cancel_secrets (NMActRequest *self, guint32 call_id)
{
	NMActRequestPrivate *priv;
	GSList *iter;

	g_return_if_fail (self);
	g_return_if_fail (NM_IS_ACT_REQUEST (self));
	g_return_if_fail (call_id > 0);

	priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	for (iter = priv->secrets_calls; iter; iter = g_slist_next (iter)) {
		GetSecretsInfo *info = iter->data;

		/* Remove the matching info */
		if (info->call_id == call_id) {
			priv->secrets_calls = g_slist_remove_link (priv->secrets_calls, iter);
			g_slist_free (iter);

			nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (priv->connection), call_id);
			g_free (info);
			break;
		}
	}
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

static void
share_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);

	nm_unblock_posix_signals (NULL);
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
		char **argv;
		char *cmd;

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
			                   share_child_setup, NULL, NULL, NULL, &status, &error)) {
				nm_log_warn (LOGD_SHARING, "Error executing command: (%d) %s",
				             error ? error->code : -1,
				             (error && error->message) ? error->message : "(unknown)");
				g_clear_error (&error);
			} else if (WEXITSTATUS (status)) {
				nm_log_warn (LOGD_SHARING, "** Command returned exit status %d.",
				             WEXITSTATUS (status));
			}
		}
		g_free (cmd);
		if (argv)
			g_strfreev (argv);
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
device_state_changed (NMDevice *device, GParamSpec *pspec, NMActRequest *self)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (self);
	NMActiveConnectionState ac_state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;

	/* Set NMActiveConnection state based on the device's state */
	switch (nm_device_get_state (device)) {
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
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		ac_state = NM_ACTIVE_CONNECTION_STATE_DEACTIVATING;
		break;
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
		ac_state = NM_ACTIVE_CONNECTION_STATE_DEACTIVATED;

		/* No longer need to pay attention to device state */
		if (priv->device && priv->device_state_id) {
			g_signal_handler_disconnect (priv->device, priv->device_state_id);
			priv->device_state_id = 0;
		}
		g_clear_object (&priv->device);
		break;
	default:
		break;
	}

	if (   ac_state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED
	    || ac_state == NM_ACTIVE_CONNECTION_STATE_UNKNOWN) {
		nm_active_connection_set_default (NM_ACTIVE_CONNECTION (self), FALSE);
		nm_active_connection_set_default6 (NM_ACTIVE_CONNECTION (self), FALSE);
	}

	nm_active_connection_set_state (NM_ACTIVE_CONNECTION (self), ac_state);
}

/********************************************************************/

/**
 * nm_act_request_new:
 *
 * @connection: the connection to activate @device with
 * @specific_object: the object path of the specific object (ie, WiFi access point,
 *    etc) that will be used to activate @connection and @device
 * @user_requested: pass %TRUE if the activation was requested via D-Bus,
 *    otherwise %FALSE if requested internally by NM (ie, autoconnect)
 * @user_uid: if @user_requested is %TRUE, the Unix UID of the user that requested
 * @dbus_sender: if @user_requested is %TRUE, the D-BUS sender that requested
 *    the activation
 * @assumed: pass %TRUE if the activation should "assume" (ie, taking over) an
 *    existing connection made before this instance of NM started
 * @device: the device/interface to configure according to @connection
 * @master: if the activation depends on another device (ie, bond or bridge
 *    master to which this device will be enslaved) pass the #NMDevice that this
 *    activation request be enslaved to
 *
 * Begins activation of @device using the given @connection and other details.
 *
 * Returns: the new activation request on success, %NULL on error.
 */
NMActRequest *
nm_act_request_new (NMConnection *connection,
                    const char *specific_object,
                    gboolean user_requested,
                    gulong user_uid,
                    const char *dbus_sender,
                    gboolean assumed,
                    NMDevice *device,
                    NMDevice *master)
{
	GObject *object;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_DEVICE (device), NULL);

	object = g_object_new (NM_TYPE_ACT_REQUEST,
	                       NM_ACTIVE_CONNECTION_INT_CONNECTION, connection,
	                       NM_ACTIVE_CONNECTION_INT_DEVICE, device,
	                       NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, specific_object,
	                       NM_ACTIVE_CONNECTION_INT_USER_REQUESTED, user_requested,
	                       NM_ACTIVE_CONNECTION_INT_USER_UID, user_uid,
	                       NM_ACTIVE_CONNECTION_INT_ASSUMED, assumed,
	                       NM_ACTIVE_CONNECTION_INT_MASTER, master,
	                       NULL);
	if (object) {
		nm_active_connection_export (NM_ACTIVE_CONNECTION (object));
		NM_ACT_REQUEST_GET_PRIVATE (object)->dbus_sender = g_strdup (dbus_sender);
	}

	return (NMActRequest *) object;
}

static void
nm_act_request_init (NMActRequest *req)
{
}

static void
constructed (GObject *object)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);
	NMConnection *connection;
	NMDevice *device;

	G_OBJECT_CLASS (nm_act_request_parent_class)->constructed (object);

	connection = nm_active_connection_get_connection (NM_ACTIVE_CONNECTION (object));
	priv->connection = g_object_ref (connection);

	device = nm_active_connection_get_device (NM_ACTIVE_CONNECTION (object));
	if (device) {
		priv->device = g_object_ref (device);
		priv->device_state_id = g_signal_connect (priv->device,
		                                          "notify::" NM_DEVICE_STATE,
		                                          G_CALLBACK (device_state_changed),
		                                          NM_ACT_REQUEST (object));
	}
}

static void
dispose (GObject *object)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);
	GSList *iter;

	if (priv->device && priv->device_state_id) {
		g_signal_handler_disconnect (priv->device, priv->device_state_id);
		priv->device_state_id = 0;
	}

	/* Clear any share rules */
	if (priv->share_rules) {
		nm_act_request_set_shared (NM_ACT_REQUEST (object), FALSE);
		clear_share_rules (NM_ACT_REQUEST (object));
	}

	/* Kill any in-progress secrets requests */
	for (iter = priv->secrets_calls; iter; iter = g_slist_next (iter)) {
		GetSecretsInfo *info = iter->data;

		g_assert (priv->connection);
		nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (priv->connection), info->call_id);
		g_free (info);
	}
	g_slist_free (priv->secrets_calls);
	priv->secrets_calls = NULL;

	g_free (priv->dbus_sender);
	priv->dbus_sender = NULL;

	g_clear_object (&priv->device);
	g_clear_object (&priv->connection);

	G_OBJECT_CLASS (nm_act_request_parent_class)->dispose (object);
}

static void
nm_act_request_class_init (NMActRequestClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (NMActRequestPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->dispose = dispose;
}

