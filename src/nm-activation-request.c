/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */


#include "nm-activation-request.h"
#include "nm-marshal.h"
#include "nm-manager.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMActRequest, nm_act_request, G_TYPE_OBJECT)

#define NM_ACT_REQUEST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACT_REQUEST, NMActRequestPrivate))

enum {
	CONNECTION_SECRETS_UPDATED,
	DEFERRED_ACTIVATION_TIMEOUT,
	DEFERRED_ACTIVATION_START,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


static void connection_secrets_updated_cb (NMConnection *connection,
                                           const char *setting_name,
                                           NMActRequest *self);

typedef struct {
	char *deferred_service_name;
	char *deferred_connection_path;
	gulong deferred_connection_id;
	guint32 deferred_timeout_id;

	NMConnection *connection;
	char *specific_object;
	gboolean user_requested;

	gulong secrets_updated_id;
} NMActRequestPrivate;

static void
nm_act_request_init (NMActRequest *req)
{
}

static void
clear_deferred_stuff (NMActRequest *req)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (req);

	g_free (priv->deferred_service_name);
	priv->deferred_service_name = NULL;
	g_free (priv->deferred_connection_path);
	priv->deferred_connection_path = NULL;

	if (priv->deferred_connection_id) {
		NMManager *manager = nm_manager_get ();
		g_signal_handler_disconnect (manager, priv->deferred_connection_id);
		g_object_unref (manager);
		priv->deferred_connection_id = 0;
	}

	if (priv->deferred_timeout_id) {
		g_source_remove (priv->deferred_timeout_id);
		priv->deferred_timeout_id = 0;
	}
}

static void
dispose (GObject *object)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);

	clear_deferred_stuff (NM_ACT_REQUEST (object));

	if (priv->secrets_updated_id) {
		g_signal_handler_disconnect (priv->connection,
		                             priv->secrets_updated_id);
		priv->secrets_updated_id = 0;
	}

	if (priv->connection)
		g_object_unref (priv->connection);
}

static void
finalize (GObject *object)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);

	g_free (priv->deferred_service_name);
	g_free (priv->deferred_connection_path);
	g_free (priv->specific_object);

	G_OBJECT_CLASS (nm_act_request_parent_class)->finalize (object);
}

static void
nm_act_request_class_init (NMActRequestClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (NMActRequestPrivate));

	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* Signals */
	signals[CONNECTION_SECRETS_UPDATED] =
		g_signal_new ("connection-secrets-updated",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMActRequestClass, connection_secrets_updated),
					  NULL, NULL,
					  nm_marshal_VOID__OBJECT_STRING,
					  G_TYPE_NONE, 2,
					  G_TYPE_OBJECT, G_TYPE_STRING);

	signals[DEFERRED_ACTIVATION_TIMEOUT] =
		g_signal_new ("deferred-activation-timeout",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMActRequestClass, deferred_activation_timeout),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0,
					  G_TYPE_NONE);

	signals[DEFERRED_ACTIVATION_START] =
		g_signal_new ("deferred-activation-start",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMActRequestClass, deferred_activation_start),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0,
					  G_TYPE_NONE);
}

NMActRequest *
nm_act_request_new (NMConnection *connection,
                    const char *specific_object,
                    gboolean user_requested)
{
	GObject *obj;
	NMActRequestPrivate *priv;
	gulong id;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	obj = g_object_new (NM_TYPE_ACT_REQUEST, NULL);
	if (!obj)
		return NULL;

	priv = NM_ACT_REQUEST_GET_PRIVATE (obj);

	priv->connection = g_object_ref (connection);
	priv->user_requested = user_requested;
	if (specific_object)
		priv->specific_object = g_strdup (specific_object);

	id = g_signal_connect (priv->connection,
	                       "secrets-updated",
	                       G_CALLBACK (connection_secrets_updated_cb),
	                       NM_ACT_REQUEST (obj));
	priv->secrets_updated_id = id;

	return NM_ACT_REQUEST (obj);
}

static gboolean
deferred_timeout_cb (gpointer data)
{
	NMActRequest *self = NM_ACT_REQUEST (data);
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (self);

	priv->deferred_timeout_id = 0;
	clear_deferred_stuff (self);

	g_signal_emit (self, signals[DEFERRED_ACTIVATION_TIMEOUT], 0);
	return FALSE;
}

static void
connection_added_cb (NMManager *manager,
                     NMConnection *connection,
                     gpointer user_data)
{
	NMActRequest *self;
	NMActRequestPrivate *priv;
	const char *service_name;
	const char *path;
	gulong id;

	g_return_if_fail (NM_IS_ACT_REQUEST (user_data));
	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (NM_IS_MANAGER (manager));

	self = NM_ACT_REQUEST (user_data);

	service_name = nm_manager_get_connection_service_name (manager, connection);
	path = nm_manager_get_connection_dbus_path (manager, connection);
	if (!service_name || !path) {
		nm_warning ("Couldn't get connection service name or path (%s, %s)",
		            service_name, path);
		return;
	}

	priv = NM_ACT_REQUEST_GET_PRIVATE (self);
	if (   strcmp (service_name, priv->deferred_service_name)
	    || strcmp (path, priv->deferred_connection_path))
		return;

	clear_deferred_stuff (self);

	priv->connection = g_object_ref (connection);
	id = g_signal_connect (priv->connection,
	                       "secrets-updated",
	                       G_CALLBACK (connection_secrets_updated_cb),
	                       self);
	priv->secrets_updated_id = id;

	g_signal_emit (self, signals[DEFERRED_ACTIVATION_START], 0);
}

NMActRequest *
nm_act_request_new_deferred (const char *service_name,
                             const char *connection_path,
                             const char *specific_object,
                             gboolean user_requested)
{
	GObject *obj;
	NMManager *manager;
	NMActRequestPrivate *priv;
	gulong id;

	g_return_val_if_fail (service_name != NULL, NULL);
	g_return_val_if_fail (connection_path != NULL, NULL);

	obj = g_object_new (NM_TYPE_ACT_REQUEST, NULL);
	if (!obj)
		return NULL;

	priv = NM_ACT_REQUEST_GET_PRIVATE (obj);

	priv->deferred_service_name = g_strdup (service_name);
	priv->deferred_connection_path = g_strdup (connection_path);
	priv->user_requested = user_requested;
	if (specific_object)
		priv->specific_object = g_strdup (specific_object);

	id = g_timeout_add (5000, deferred_timeout_cb, NM_ACT_REQUEST (obj));
	priv->deferred_timeout_id = id;

	manager = nm_manager_get ();
	id = g_signal_connect (manager,
	                       "connection-added",
	                       G_CALLBACK (connection_added_cb),
	                       NM_ACT_REQUEST (obj));
	priv->deferred_connection_id = id;
	g_object_unref (manager);

	return NM_ACT_REQUEST (obj);
}

static void
connection_secrets_updated_cb (NMConnection *connection,
                               const char *setting_name,
                               NMActRequest *self)
{
	g_return_if_fail (setting_name != NULL);
	g_return_if_fail (self != NULL);

	g_signal_emit (self, signals[CONNECTION_SECRETS_UPDATED], 0, connection, setting_name);
}

NMConnection *
nm_act_request_get_connection (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->connection;
}

const char *
nm_act_request_get_specific_object (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NULL);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->specific_object;
}

gboolean
nm_act_request_get_user_requested (NMActRequest *req)
{
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	return NM_ACT_REQUEST_GET_PRIVATE (req)->user_requested;
}
