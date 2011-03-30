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

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "NetworkManager.h"
#include "nm-secret-agent.h"
#include "nm-dbus-glib-types.h"

G_DEFINE_TYPE (NMSecretAgent, nm_secret_agent, G_TYPE_OBJECT)

#define NM_SECRET_AGENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                        NM_TYPE_SECRET_AGENT, \
                                        NMSecretAgentPrivate))

typedef struct {
	gboolean disposed;

	char *description;
	char *owner;
	char *identifier;
	uid_t owner_uid;
	guint32 hash;

	NMDBusManager *dbus_mgr;
	DBusGProxy *proxy;

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

	g_return_val_if_fail (agent != NULL, NULL);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (agent);
	if (!priv->description) {
		priv->description = g_strdup_printf ("%s/%s/%u",
		                                     priv->owner,
		                                     priv->identifier,
		                                     priv->owner_uid);
	}

	return priv->description;
}

const char *
nm_secret_agent_get_dbus_owner (NMSecretAgent *agent)
{
	g_return_val_if_fail (agent != NULL, NULL);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->owner;
}

const char *
nm_secret_agent_get_identifier (NMSecretAgent *agent)
{
	g_return_val_if_fail (agent != NULL, NULL);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), NULL);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->identifier;
}

uid_t
nm_secret_agent_get_owner_uid  (NMSecretAgent *agent)
{
	g_return_val_if_fail (agent != NULL, G_MAXUINT);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), G_MAXUINT);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->owner_uid;
}

guint32
nm_secret_agent_get_hash  (NMSecretAgent *agent)
{
	g_return_val_if_fail (agent != NULL, 0);
	g_return_val_if_fail (NM_IS_SECRET_AGENT (agent), 0);

	return NM_SECRET_AGENT_GET_PRIVATE (agent)->hash;
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
                             const char *hint,
                             NMSettingsGetSecretsFlags flags,
                             NMSecretAgentCallback callback,
                             gpointer callback_data)
{
	NMSecretAgentPrivate *priv;
	GHashTable *hash;
	const char *hints[2] = { hint, NULL };
	Request *r;

	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (setting_name != NULL, NULL);

	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	hash = nm_connection_to_hash (connection, NM_SETTING_HASH_FLAG_ALL);

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

void
nm_secret_agent_cancel_secrets (NMSecretAgent *self, gconstpointer call)
{
	NMSecretAgentPrivate *priv;
	Request *r;

	g_return_if_fail (self != NULL);
	priv = NM_SECRET_AGENT_GET_PRIVATE (self);

	r = g_hash_table_lookup (priv->requests, call);
	g_return_if_fail (r != NULL);

	dbus_g_proxy_cancel_call (NM_SECRET_AGENT_GET_PRIVATE (self)->proxy, (gpointer) call);

	dbus_g_proxy_call_no_reply (priv->proxy,
	                            "CancelGetSecrets",
	                            G_TYPE_STRING, r->path,
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

/*************************************************************/

NMSecretAgent *
nm_secret_agent_new (NMDBusManager *dbus_mgr,
                     const char *owner,
                     const char *identifier,
                     uid_t owner_uid)
{
	NMSecretAgent *self;
	NMSecretAgentPrivate *priv;
	DBusGConnection *bus;
	char *hash_str;

	g_return_val_if_fail (owner != NULL, NULL);
	g_return_val_if_fail (identifier != NULL, NULL);

	self = (NMSecretAgent *) g_object_new (NM_TYPE_SECRET_AGENT, NULL);
	if (self) {
		priv = NM_SECRET_AGENT_GET_PRIVATE (self);

		priv->owner = g_strdup (owner);
		priv->identifier = g_strdup (identifier);
		priv->owner_uid = owner_uid;

		hash_str = g_strdup_printf ("%08u%s", owner_uid, identifier);
		priv->hash = g_str_hash (hash_str);
		g_free (hash_str);

		priv->dbus_mgr = g_object_ref (dbus_mgr);
		bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
		priv->proxy = dbus_g_proxy_new_for_name (bus,
	                                             owner,
	                                             NM_DBUS_PATH_SECRET_AGENT,
	                                             NM_DBUS_INTERFACE_SECRET_AGENT);
		g_assert (priv->proxy);
	}

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

	if (!priv->disposed) {
		priv->disposed = TRUE;

		g_free (priv->description);
		g_free (priv->owner);
		g_free (priv->identifier);

		g_hash_table_destroy (priv->requests);
		g_object_unref (priv->proxy);
		g_object_unref (priv->dbus_mgr);
	}

	G_OBJECT_CLASS (nm_secret_agent_parent_class)->dispose (object);
}

static void
nm_secret_agent_class_init (NMSecretAgentClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMSecretAgentPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}

