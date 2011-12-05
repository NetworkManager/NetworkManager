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
 * Copyright (C) 2011 Thomas Bechtold <thomasbechtold@jpberlin.de>
 */

#include <config.h>

#include <string.h>
#include <libsoup/soup.h>

#include "nm-connectivity.h"
#include "nm-logging.h"
#include "nm-manager.h"


typedef struct {
	/* used for http requests */
	SoupSession *soup_session;
	/* indicates if a connectivity check is currently running */
	gboolean check_running;
	/* the uri to check */
	const gchar *check_uri;
	/* seconds when a check will be repeated */
	guint check_interval;
	/* the expected response for the connectivity check */
	const gchar *check_response;
	/* indicates if the last connection check was successful */
	gboolean connected;
	/* the source id for the periodic check */
	guint check_interval_source_id;

} NMConnectivityPrivate;

G_DEFINE_TYPE (NMConnectivity, nm_connectivity, G_TYPE_OBJECT)

#define NM_CONNECTIVITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONNECTIVITY, NMConnectivityPrivate))


enum {
	CONNECTED_CHANGED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_CHECK_RUNNING,
	PROP_CHECK_URI,
	PROP_CHECK_INTERVAL,
	PROP_CHECK_RESPONSE,
	PROP_CONNECTED,
	LAST_PROP
};


gboolean
nm_connectivity_get_connected (NMConnectivity *connectivity)
{
	g_return_val_if_fail (NM_IS_CONNECTIVITY (connectivity), FALSE);
	return NM_CONNECTIVITY_GET_PRIVATE (connectivity)->connected;
}

static gboolean
nm_connectivity_interval (NMConnectivity *connectivity)
{
	/* periodically check connectivity */
	nm_connectivity_check (connectivity);
	return TRUE;
}


static void
nm_connectivity_check_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	NMConnectivity *connectivity;
	NMConnectivityPrivate *priv;
	SoupURI *soup_uri;
	gboolean connected_new;

	g_return_if_fail (NM_IS_CONNECTIVITY (user_data));
	connectivity = NM_CONNECTIVITY (user_data);
	priv = NM_CONNECTIVITY_GET_PRIVATE (connectivity);

	soup_uri = soup_message_get_uri (msg);

	/* check response */
	if (msg->response_body->data &&	(g_str_has_prefix (msg->response_body->data, priv->check_response))) {
		nm_log_dbg (LOGD_CORE, "Connectivity check for uri '%s' with expected response '%s' successful.",
		            soup_uri_to_string (soup_uri, FALSE),
		            priv->check_response);
		connected_new = TRUE;
	} else {
		nm_log_dbg (LOGD_CORE, "Connectivity check for uri '%s' with expected response '%s' failed.",
					soup_uri_to_string (soup_uri, FALSE),
					priv->check_response);
		connected_new = FALSE;
	}

	/* update connectivity and emit signal */
	if (priv->connected != connected_new) {
		priv->connected = connected_new;
		g_object_notify (G_OBJECT (connectivity), NM_CONNECTIVITY_CONNECTED);
		g_signal_emit_by_name (connectivity, NM_CONNECTIVITY_SIGNAL_CONNECTED_CHANGED, priv->connected);
	}

	priv->check_running = FALSE;
	g_object_notify (G_OBJECT (connectivity), NM_CONNECTIVITY_CHECK_RUNNING);
}


void
nm_connectivity_check (NMConnectivity *connectivity)
{
	NMConnectivityPrivate *priv;
	SoupURI *soup_uri;
	SoupMessage *connectivity_check_msg;

	g_return_if_fail (NM_IS_CONNECTIVITY (connectivity));
	priv = NM_CONNECTIVITY_GET_PRIVATE (connectivity);

	if (priv->check_running) return;

	if (priv->check_uri
	    && strlen (priv->check_uri)
	    && priv->check_response
	    && strlen (priv->check_response)) {
		/* check given url async */
		soup_uri = soup_uri_new (priv->check_uri);
		if (soup_uri && SOUP_URI_VALID_FOR_HTTP (soup_uri)) {
			connectivity_check_msg = soup_message_new_from_uri ("GET", soup_uri);
			soup_session_queue_message (priv->soup_session,
			                            connectivity_check_msg,
			                            nm_connectivity_check_cb,
			                            connectivity);

			priv->check_running = TRUE;
			g_object_notify (G_OBJECT (connectivity), NM_CONNECTIVITY_CHECK_RUNNING);
			nm_log_dbg (LOGD_CORE, "connectivity check with uri '%s' started.", priv->check_uri);
			soup_uri_free (soup_uri);
		} else
			nm_log_err (LOGD_CORE, "Invalid uri '%s' for connectivity check.", priv->check_uri);
	} else {
		/* no uri/response given - default is connected so nm-manager can set NMState to GLOBAL */
		if (!priv->connected) {
			priv->connected = TRUE;
			g_object_notify (G_OBJECT (connectivity), NM_CONNECTIVITY_CONNECTED);
			g_signal_emit_by_name (connectivity, NM_CONNECTIVITY_SIGNAL_CONNECTED_CHANGED, priv->connected);
		}
	}
}


NMConnectivity*
nm_connectivity_new (const gchar *check_uri,
                     guint check_interval,
                     const gchar *check_response)
{
	NMConnectivity *connectivity = g_object_new (NM_TYPE_CONNECTIVITY, NULL);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (connectivity);

	priv->check_uri = check_uri;
	priv->check_interval = check_interval;
	priv->check_response = check_response;

	if (check_uri && strlen (check_uri) && (check_interval > 0)) {
		priv->check_interval_source_id = g_timeout_add_seconds (check_interval,
		                                                        (GSourceFunc) nm_connectivity_interval,
		                                                        connectivity);
	} else
		priv->check_interval_source_id = 0;

	return connectivity;
}


static void
nm_connectivity_set_property (GObject *object, guint property_id,
                              const GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	switch (property_id) {
	case PROP_CHECK_RUNNING:
		priv->check_running = g_value_get_boolean (value);
		break;
	case PROP_CHECK_URI:
		priv->check_uri = g_value_get_string (value);
		break;
	case PROP_CHECK_INTERVAL:
		priv->check_interval = g_value_get_uint (value);
		break;
	case PROP_CHECK_RESPONSE:
		priv->check_response = g_value_get_string (value);
		break;
	case PROP_CONNECTED:
		priv->connected = g_value_get_boolean (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}

static void
nm_connectivity_get_property (GObject *object, guint property_id,
                              GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	switch (property_id) {
	case PROP_CHECK_RUNNING:
		g_value_set_boolean (value, priv->check_running);
		break;
	case PROP_CHECK_URI:
		g_value_set_static_string (value, priv->check_uri);
		break;
	case PROP_CHECK_INTERVAL:
		g_value_set_uint (value, priv->check_interval);
		break;
	case PROP_CHECK_RESPONSE:
		g_value_set_static_string (value, priv->check_response);
		break;
	case PROP_CONNECTED:
		g_value_set_boolean (value, priv->connected);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
		break;
	}
}


static void
nm_connectivity_init (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	priv->soup_session = soup_session_async_new ();
}


static void
nm_connectivity_dispose (GObject *object)
{
	NMConnectivity *connectivity = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (connectivity);

	if (priv->soup_session) {
		soup_session_abort (priv->soup_session);
		g_object_unref (priv->soup_session);
		priv->soup_session = NULL;
	}

	priv->check_running = FALSE;
	priv->connected = FALSE;

	priv->check_uri = NULL;
	priv->check_interval = 0;
	priv->check_response = NULL;

	if (priv->check_interval_source_id > 0) {
		g_warn_if_fail (g_source_remove (priv->check_interval_source_id) == TRUE);
		priv->check_interval_source_id = 0;
	}
}


static void
nm_connectivity_class_init (NMConnectivityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	g_type_class_add_private (klass, sizeof (NMConnectivityPrivate));

	/* virtual methods */
	object_class->set_property = nm_connectivity_set_property;
	object_class->get_property = nm_connectivity_get_property;
	object_class->dispose = nm_connectivity_dispose;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_CHECK_RUNNING,
		 g_param_spec_string (NM_CONNECTIVITY_CHECK_RUNNING,
		                      "Running",
		                      "Is Connectivity chunk running",
		                      NULL,
		                      G_PARAM_READABLE));
	g_object_class_install_property
		(object_class, PROP_CHECK_URI,
		 g_param_spec_string (NM_CONNECTIVITY_CHECK_URI,
		                      "URI",
		                      "Connectivity check URI",
		                      NULL,
		                      G_PARAM_READWRITE));
	g_object_class_install_property
		(object_class, PROP_CHECK_INTERVAL,
		 g_param_spec_uint (NM_CONNECTIVITY_CHECK_INTERVAL,
		                    "Interval",
		                    "Connectivity check interval in seconds",
		                    0,
		                    G_MAXUINT,
		                    300,
		                    G_PARAM_READWRITE));
	g_object_class_install_property
		(object_class, PROP_CHECK_RESPONSE,
		 g_param_spec_string (NM_CONNECTIVITY_CHECK_RESPONSE,
		                      "REsponse",
		                      "Connectivity check reponse",
		                      NULL,
		                      G_PARAM_READWRITE));
	g_object_class_install_property
		(object_class, PROP_CONNECTED,
		 g_param_spec_string (NM_CONNECTIVITY_CONNECTED,
		                      "Connected",
		                      "Is connected",
		                      NULL,
		                      G_PARAM_READABLE));

	/* signals */
	signals[CONNECTED_CHANGED] =
		g_signal_new (NM_CONNECTIVITY_SIGNAL_CONNECTED_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMConnectivityClass, connected_changed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__BOOLEAN,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);
}

