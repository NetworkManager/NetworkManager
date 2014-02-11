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
 * Copyright (C) 2010 - 2011 Red Hat, Inc.
 */

#include <config.h>

#include <sys/types.h>
#include <pwd.h>

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "NetworkManager.h"
#include "nm-secret-agent.h"
#include "nm-dbus-manager.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"
#include "nm-logging.h"

G_DEFINE_TYPE (NMSecretAgent, nm_secret_agent, G_TYPE_OBJECT)

#define NM_SECRET_AGENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_SECRET_AGENT, \
                                        NMSecretAgentPrivate))

typedef struct {
	char *description;
	NMAuthSubject *subject;
	char *identifier;
	char *owner_username;
	NMSecretAgentCapabilities capabilities;
	guint32 hash;

	GSList *permissions;

	DBusGProxy *proxy;
	guint proxy_destroy_id;

	GHashTable *requests;
} NMSecretAgentPrivate;

/*************************************************************/

typedef struct {
	NMSecretAgent *agent;
	DBusGProxyCall *call;
	char *path;
	char *setting_name;
	NMSecretAgentCallback callback;
	gpointer callback_data;
} Request;

static Request *
request_new (NMSecretAgent *agent,
             const char *path,
             const char *setting_name,
             NMSecretAgentCallback callback,
             gpointer callback_data)
{
	Request *r;

	r = g_slice_new0 (Request);
	r->agent = agent;
	r->path = g_strdup (path);
	r->setting_name = g_strdup (setting_name);
	r->callback = callback;
	r->callback_data = callback_data;
	return r;
}

static void
request_free (Request *r)
{
	g_free (r->path);
	g_free (r->setting_name);
	g_slice_free (Request, r);
}

/*************************************************************/

const char *
nm_secret_agent_get_description (NMSecretAgent *agent)
{
	NMSecretAgentPrivate *priv;

	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);
	if (!priv->description) {
		priv->description = g_strdup_printf ("%s/%s/%lu",
		                                     nm_auth_subject_get_dbus_sender (priv->subject),
		                                     priv->identifier,
		                                     nm_auth_subject_get_uid (priv->subject));
	}

	return priv->description;
}

const char *
nm_secret_agent_get_dbus_owner (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return nm_auth_subject_get_dbus_sender (NM_SECRET_AGENT_GET_PRIVATE (agent)->subject);
}

const char *
nm_secret_agent_get_identifier (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->identifier;
}

gulong
nm_secret_agent_get_owner_uid  (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), G_MAXULONG);

	return nm_auth_subject_get_uid (NM_SECRET_AGENT_GET_PRIVATE (agent)->subject);
}

const char *
nm_secret_agent_get_owner_username (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->owner_username;
}

gulong
nm_secret_agent_get_pid (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), G_MAXULONG);

	return nm_auth_subject_get_pid (NM_SECRET_AGENT_GET_PRIVATE (agent)->subject);
}

NMSecretAgentCapabilities
nm_secret_agent_get_capabilities (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NM_SECRET_AGENT_CAPABILITY_NONE);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->capabilities;
}

guint32
nm_secret_agent_get_hash (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), 0);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->hash;
}

NMAuthSubject *
nm_secret_agent_get_subject (NMSecretAgent *agent)
{
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->subject;
}

/**
 * nm_secret_agent_add_permission:
 * @agent: A #NMSecretAgent.
 * @permission: The name of the permission
 *
 * Records whether or not the agent has a given permission.
 */
void
nm_secret_agent_add_permission (NMSecretAgent *agent,
                                const char *permission,
                                gboolean allowed)
{
	NMSecretAgentPrivate *priv;
	GSList *iter;

	g_return_if_fail (agent != NULL);
	g_return_if_fail (permission != NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);

	/* Check if the permission is already in the list */
	for (iter = priv->permissions; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (permission, iter->data) == 0) {
			/* If the permission is no longer allowed, remove it from the
			 * list.  If it is now allowed, do nothing since it's already
			 * in the list.
			 */
			if (allowed == FALSE) {
				g_free (iter->data);
				priv->permissions = g_slist_delete_link (priv->permissions, iter);
			}
			return;
		}
	}

	/* New permission that's allowed */
	if (allowed)
		priv->permissions = g_slist_prepend (priv->permissions, g_strdup (permission));
}

/**
 * nm_secret_agent_has_permission:
 * @agent: A #NMSecretAgent.
 * @permission: The name of the permission to check for
 *
 * Returns whether or not the agent has the given permission.
 * 
 * Returns: %TRUE if the agent has the given permission, %FALSE if it does not
 * or if the permission was not previous recorded with
 * nm_secret_agent_add_permission().
 */
gboolean
nm_secret_agent_has_permission (NMSecretAgent *agent, const char *permission)
{
	NMSecretAgentPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (agent != NULL, FALSE);
	g_return_val_if_fail (permission != NULL, FALSE);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);

	/* Check if the permission is already in the list */
	for (iter = priv->permissions; iter; iter = g_slist_next (iter)) {
		if (g_strcmp0 (permission, iter->data) == 0)
			return TRUE;
	}
	return FALSE;
}

/*************************************************************/

static void
get_callback (DBusGProxy *proxy,
              DBusGProxyCall *call,
              void *user_data)
{
	Request *r = user_data;
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (r->agent);
	GError *error = NULL;
	GHashTable *secrets = NULL;

	g_return_if_fail (call == r->call);

	dbus_g_proxy_end_call (proxy, call, &error,
	                       DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &secrets,
	                       G_TYPE_INVALID);
	r->callback (r->agent, r->call, secrets, error, r->callback_data);
	if (secrets)
		g_hash_table_unref (secrets);
	g_clear_error (&error);
	g_hash_table_remove (priv->requests, call);
}

gconstpointer
nm_secret_agent_get_secrets (NMSecretAgent *self,
                             NMConnection *connection,
                             const char *setting_name,
                             const char **hints,
                             NMSettingsGetSecretsFlags flags,
                             NMSecretAgentCallback callback,
                             gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GHashTable *hash;
	Request *r;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (setting_name != NULL, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	g_return_val_if_fail (priv->proxy != NULL, NULL);

	hash = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

	/* Mask off the private ONLY_SYSTEM flag if present */
	flags &= ~NM_SETTINGS_GET_SECRETS_FLAG_ONLY_SYSTEM;

	r = request_new (self, nm_connection_get_path (connection), setting_name, callback, callback_data);
	r->call = dbus_g_proxy_begin_call_with_timeout (priv->proxy,
	                                                "GetSecrets",
	                                                get_callback,
	                                                r,
	                                                NULL,
	                                                120000, /* 120 seconds */
	                                                DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, hash,
	                                                DBUS_TYPE_G_OBJECT_PATH, nm_connection_get_path (connection),
	                                                G_TYPE_STRING, setting_name,
	                                                G_TYPE_STRV, hints,
	                                                G_TYPE_UINT, flags,
	                                                G_TYPE_INVALID);
	g_hash_table_insert (priv->requests, r->call, r);

	g_hash_table_destroy (hash);
	return r->call;
}

static void
cancel_done (DBusGProxy *proxy, DBusGProxyCall *call_id, void *user_data)
{
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		nm_log_dbg (LOGD_AGENTS, "(%s): agent failed to cancel secrets: (%d) %s",
		            (const char *) user_data,
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

void
nm_secret_agent_cancel_secrets (NMSecretAgent *self, gconstpointer call)
{
	NMSecretAgentPrivate *priv;
	Request *r;

	g_return_if_fail (self != NULL);
	priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	g_return_if_fail (priv->proxy != NULL);

	r = g_hash_table_lookup (priv->requests, call);
	g_return_if_fail (r != NULL);

	dbus_g_proxy_cancel_call (priv->proxy, (gpointer) call);

	dbus_g_proxy_begin_call (priv->proxy,
	                         "CancelGetSecrets",
	                         cancel_done,
	                         g_strdup (nm_secret_agent_get_description (self)),
	                         g_free,
	                         DBUS_TYPE_G_OBJECT_PATH, r->path,
	                         G_TYPE_STRING, r->setting_name,
	                         G_TYPE_INVALID);
	g_hash_table_remove (priv->requests, call);
}

/*************************************************************/

static void
agent_save_delete_cb (DBusGProxy *proxy,
                      DBusGProxyCall *call,
                      void *user_data)
{
	Request *r = user_data;
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (r->agent);
	GError *error = NULL;

	g_return_if_fail (call == r->call);

	dbus_g_proxy_end_call (proxy, call, &error, G_TYPE_INVALID);
	r->callback (r->agent, r->call, NULL, error, r->callback_data);
	g_clear_error (&error);
	g_hash_table_remove (priv->requests, call);
}

static gpointer
agent_new_save_delete (NMSecretAgent *self,
                       NMConnection *connection,
                       NMSettingHashFlags hash_flags,
                       const char *method,
                       NMSecretAgentCallback callback,
                       gpointer callback_data)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);
	GHashTable *hash;
	Request *r;
	const char *cpath = nm_connection_get_path (connection);

	hash = nm_connection_to_hash (connection, hash_flags);

	r = request_new (self, cpath, NULL, callback, callback_data);
	r->call = dbus_g_proxy_begin_call_with_timeout (priv->proxy,
	                                                method,
	                                                agent_save_delete_cb,
	                                                r,
	                                                NULL,
	                                                10000, /* 10 seconds */
	                                                DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, hash,
	                                                DBUS_TYPE_G_OBJECT_PATH, cpath,
	                                                G_TYPE_INVALID);
	g_hash_table_insert (priv->requests, r->call, r);

	g_hash_table_destroy (hash);
	return r->call;
}

gconstpointer
nm_secret_agent_save_secrets (NMSecretAgent *self,
                              NMConnection *connection,
                              NMSecretAgentCallback callback,
                              gpointer callback_data)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	/* Caller should have ensured that only agent-owned secrets exist in 'connection' */
	return agent_new_save_delete (self,
	                              connection,
	                              NM_SETTING_HASH_FLAG_ALL,
	                              "SaveSecrets",
	                              callback,
	                              callback_data);
}

gconstpointer
nm_secret_agent_delete_secrets (NMSecretAgent *self,
                                NMConnection *connection,
                                NMSecretAgentCallback callback,
                                gpointer callback_data)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);

	/* No secrets sent; agents must be smart enough to track secrets using the UUID or something */
	return agent_new_save_delete (self,
	                              connection,
	                              NM_SETTING_HASH_FLAG_NO_SECRETS,
	                              "DeleteSecrets",
	                              callback,
	                              callback_data);
}

static void
proxy_cleanup (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	if (priv->proxy) {
		g_signal_handler_disconnect (priv->proxy, priv->proxy_destroy_id);
		priv->proxy_destroy_id = 0;
		g_clear_object (&priv->proxy);
	}
}

/*************************************************************/

NMSecretAgent *
nm_secret_agent_new (DBusGMethodInvocation *context,
                     NMAuthSubject *subject,
                     const char *identifier,
                     NMSecretAgentCapabilities capabilities)
{
	NMSecretAgent *self;
	NMSecretAgentPrivate *priv;
	char *hash_str, *username;
	struct passwd *pw;

	g_return_val_if_fail (context != NULL, NULL);
	g_return_val_if_fail (NM_IS_AUTH_SUBJECT (subject), NULL);
	g_return_val_if_fail (identifier != NULL, NULL);

	pw = getpwuid (nm_auth_subject_get_uid (subject));
	g_return_val_if_fail (pw != NULL, NULL);
	g_return_val_if_fail (pw->pw_name[0] != '\0', NULL);
	username = g_strdup (pw->pw_name);

	self = (NMSecretAgent *) g_object_new (NM_TYPE_SECRET_AGENT, NULL);
	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->identifier = g_strdup (identifier);
	priv->owner_username = g_strdup (username);
	priv->capabilities = capabilities;
	priv->subject = g_object_ref (subject);

	hash_str = g_strdup_printf ("%16lu%s", nm_auth_subject_get_uid (subject), identifier);
	priv->hash = g_str_hash (hash_str);
	g_free (hash_str);

	priv->proxy = nm_dbus_manager_new_proxy (nm_dbus_manager_get (),
	                                         context,
	                                         nm_auth_subject_get_dbus_sender (subject),
	                                         NM_DBUS_PATH_SECRET_AGENT,
	                                         NM_DBUS_INTERFACE_SECRET_AGENT);
	g_assert (priv->proxy);
	priv->proxy_destroy_id = g_signal_connect_swapped (priv->proxy, "destroy",
	                                                   G_CALLBACK (proxy_cleanup), self);

	g_free (username);
	return self;
}

static void
nm_secret_agent_init (NMSecretAgent *self)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	priv->requests = g_hash_table_new_full (g_direct_hash, g_direct_equal,
	                                        NULL, (GDestroyNotify) request_free);
}

static void
dispose (GObject *object)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (object);

	proxy_cleanup (NM_SECRET_AGENT (object));
	g_clear_object (&priv->subject);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMSecretAgentPrivate *priv = NM_SECRET_AGENT_GET_PRIVATE (object);

	g_free (priv->description);
	g_free (priv->identifier);
	g_free (priv->owner_username);

	g_slist_free_full (priv->permissions, g_free);
	g_hash_table_destroy (priv->requests);

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->finalize (object);
}

static void
nm_secret_agent_class_init (NMSecretAgentClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMSecretAgentPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
}

