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
#include "nm-marshal.h"
#include "nm-logging.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "nm-dbus-manager.h"
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
	gboolean disposed;

	NMConnection *connection;

	GSList *secrets_calls;

	NMDevice *device;
	gboolean user_requested;
	gulong user_uid;

	NMActiveConnection *dep;
	guint dep_state_id;

	gboolean shared;
	GSList *share_rules;

	gboolean assumed;
} NMActRequestPrivate;

enum {
	PROP_MASTER = 2000,
};

enum {
	DEP_RESULT,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

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

	g_return_val_if_fail (self, 0);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (self), 0);

	priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	info = g_malloc0 (sizeof (GetSecretsInfo));
	info->self = self;
	info->callback = callback;
	info->callback_data = callback_data;

	call_id = nm_settings_connection_get_secrets (NM_SETTINGS_CONNECTION (priv->connection),
	                                              priv->user_requested,
	                                              priv->user_uid,
	                                              setting_name,
	                                              flags,
	                                              hint,
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

/*******************************************************************/

NMConnection *
nm_act_request_get_connection (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->connection;
}

gboolean
nm_act_request_get_user_requested (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->user_requested;
}

GObject *
nm_act_request_get_device (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return G_OBJECT (NM_ACT_REQUEST_GET_PRIVATE (req)->device);
}

gboolean
nm_act_request_get_assumed (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->assumed;
}

NMActiveConnection *
nm_act_request_get_dependency (NMActRequest *req)
{
	return NM_ACT_REQUEST_GET_PRIVATE (req)->dep;
}

static NMActRequestDependencyResult
ac_state_to_dep_result (NMActiveConnection *ac)
{
	NMActiveConnectionState state = nm_active_connection_get_state (ac);

	if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATING)
		return NM_ACT_REQUEST_DEP_RESULT_WAIT;
	else if (state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED)
		return NM_ACT_REQUEST_DEP_RESULT_READY;

	return NM_ACT_REQUEST_DEP_RESULT_FAILED;
}

NMActRequestDependencyResult
nm_act_request_get_dependency_result (NMActRequest *req)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (req);

	return priv->dep ? ac_state_to_dep_result (priv->dep) : NM_ACT_REQUEST_DEP_RESULT_READY;
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
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMActRequest *self = NM_ACT_REQUEST (user_data);
	NMActiveConnectionState new_ac_state;

	/* Set NMActiveConnection state based on the device's state */
	switch (new_state) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
		break;
	case NM_DEVICE_STATE_ACTIVATED:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
		break;
	case NM_DEVICE_STATE_DEACTIVATING:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_DEACTIVATING;
		break;
	default:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
		nm_active_connection_set_default (NM_ACTIVE_CONNECTION (self), FALSE);
		nm_active_connection_set_default6 (NM_ACTIVE_CONNECTION (self), FALSE);
		break;
	}

	nm_active_connection_set_state (NM_ACTIVE_CONNECTION (self), new_ac_state);
}

/********************************************************************/

static void
dep_gone (NMActRequest *self, GObject *ignored)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	g_warn_if_fail (G_OBJECT (priv->dep) == ignored);

	/* Dependent connection is gone; clean up and fail */
	priv->dep = NULL;
	priv->dep_state_id = 0;
	g_signal_emit (self, signals[DEP_RESULT], 0, NM_ACT_REQUEST_DEP_RESULT_FAILED);
}

static void
dep_state_changed (NMActiveConnection *dep,
                   GParamSpec *pspec,
                   NMActRequest *self)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (self);
	NMActRequestDependencyResult result;

	g_warn_if_fail (priv->dep == dep);

	result = ac_state_to_dep_result (priv->dep);
	if (result == NM_ACT_REQUEST_DEP_RESULT_FAILED) {
		g_object_weak_unref (G_OBJECT (priv->dep), (GWeakNotify) dep_gone, self);
		g_signal_handler_disconnect (priv->dep, priv->dep_state_id);
		priv->dep = NULL;
		priv->dep_state_id = 0;
	}
	g_signal_emit (self, signals[DEP_RESULT], 0, result);
}

/**
 * nm_act_request_new:
 *
 * @connection: the connection to activate @device with
 * @specific_object: the object path of the specific object (ie, WiFi access point,
 *    etc) that will be used to activate @connection and @device
 * @user_requested: pass %TRUE if the activation was requested via D-Bus,
 *    otherwise %FALSE if requested internally by NM (ie, autoconnect)
 * @user_uid: if @user_requested is %TRUE, the Unix UID of the user that requested
 *    the activation
 * @assumed: pass %TRUE if the activation should "assume" (ie, taking over) an
 *    existing connection made before this instance of NM started
 * @device: the device/interface to configure according to @connection
 * @dependency: if the activation depends on another device (ie, VLAN slave,
 *    bond slave, etc) pass the #NMActiveConnection that this activation request
 *    should wait for before proceeding
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
                    gboolean assumed,
                    gpointer *device,
                    NMActiveConnection *dependency)
{
	GObject *object;
	NMActRequestPrivate *priv;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (NM_DEVICE (device), NULL);

	object = g_object_new (NM_TYPE_ACT_REQUEST,
	                       NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT, specific_object,
	                       NULL);
	if (!object)
		return NULL;

	priv = NM_ACT_REQUEST_GET_PRIVATE (object);

	priv->connection = g_object_ref (connection);
	priv->device = NM_DEVICE (device);
	g_signal_connect (device, "state-changed",
	                  G_CALLBACK (device_state_changed),
	                  NM_ACT_REQUEST (object));

	priv->user_uid = user_uid;
	priv->user_requested = user_requested;
	priv->assumed = assumed;

	if (dependency) {
		priv->dep = dependency;
		g_object_weak_ref (G_OBJECT (dependency), (GWeakNotify) dep_gone, object);
		priv->dep_state_id = g_signal_connect (dependency,
		                                       "notify::" NM_ACTIVE_CONNECTION_STATE,
		                                       G_CALLBACK (dep_state_changed),
		                                       object);
	}

	if (!nm_active_connection_export (NM_ACTIVE_CONNECTION (object),
	                                  connection,
	                                  nm_device_get_path (NM_DEVICE (device)))) {
		g_object_unref (object);
		object = NULL;
	}

	return (NMActRequest *) object;
}

static void
nm_act_request_init (NMActRequest *req)
{
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);
	NMDevice *master;

	switch (prop_id) {
	case PROP_MASTER:
		if (priv->dep && NM_IS_ACT_REQUEST (priv->dep)) {
			master = NM_DEVICE (nm_act_request_get_device (NM_ACT_REQUEST (priv->dep)));
			g_assert (master);
			g_value_set_boxed (value, nm_device_get_path (master));
		} else
			g_value_set_boxed (value, "/");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);
	GSList *iter;

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_act_request_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_signal_handlers_disconnect_by_func (G_OBJECT (priv->device),
	                                      G_CALLBACK (device_state_changed),
	                                      NM_ACT_REQUEST (object));

	/* Clear any share rules */
	nm_act_request_set_shared (NM_ACT_REQUEST (object), FALSE);

	/* Kill any in-progress secrets requests */
	g_assert (priv->connection);
	for (iter = priv->secrets_calls; iter; iter = g_slist_next (iter)) {
		GetSecretsInfo *info = iter->data;

		nm_settings_connection_cancel_secrets (NM_SETTINGS_CONNECTION (priv->connection), info->call_id);
		g_free (info);
	}
	g_slist_free (priv->secrets_calls);

	g_object_unref (priv->connection);

	if (priv->dep) {
		g_object_weak_unref (G_OBJECT (priv->dep), (GWeakNotify) dep_gone, object);
		g_signal_handler_disconnect (priv->dep, priv->dep_state_id);
		priv->dep = NULL;
		priv->dep_state_id = 0;
	}

	G_OBJECT_CLASS (nm_act_request_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	clear_share_rules (NM_ACT_REQUEST (object));

	G_OBJECT_CLASS (nm_act_request_parent_class)->finalize (object);
}

static void
nm_act_request_class_init (NMActRequestClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (NMActRequestPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	g_object_class_override_property (object_class, PROP_MASTER, NM_ACTIVE_CONNECTION_MASTER);

	signals[DEP_RESULT] =
		g_signal_new (NM_ACT_REQUEST_DEPENDENCY_RESULT,
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  0, NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1, G_TYPE_UINT);
}

