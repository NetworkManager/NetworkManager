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

G_DEFINE_TYPE (NMActRequest, nm_act_request, G_TYPE_OBJECT)

#define NM_ACT_REQUEST_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACT_REQUEST, NMActRequestPrivate))

enum {
	CONNECTION_SECRETS_UPDATED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


static void connection_secrets_updated_cb (NMConnection *connection,
                                           const char *setting_name,
                                           NMActRequest *self);

typedef struct {
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
finalize (GObject *object)
{
	NMActRequestPrivate *priv = NM_ACT_REQUEST_GET_PRIVATE (object);

	g_signal_handler_disconnect (priv->connection,
	                             priv->secrets_updated_id);
	g_object_unref (priv->connection);

	g_free (priv->specific_object);

	G_OBJECT_CLASS (nm_act_request_parent_class)->finalize (object);
}

static void
nm_act_request_class_init (NMActRequestClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (NMActRequestPrivate));

	object_class->finalize = finalize;

	/* Signals */
	signals[CONNECTION_SECRETS_UPDATED] =
		g_signal_new ("connection-secrets-updated",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMConnectionClass, secrets_updated),
					  NULL, NULL,
					  nm_marshal_VOID__OBJECT_STRING,
					  G_TYPE_NONE, 2,
					  G_TYPE_OBJECT, G_TYPE_STRING);
}

NMActRequest *
nm_act_request_new (NMConnection *connection,
                    const char *specific_object,
                    gboolean user_requested)
{
	GObject *obj;
	NMActRequestPrivate *priv;
	gulong id;

	g_return_val_if_fail (connection != NULL, NULL);

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
