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
 * Copyright (C) 2011 Dan Williams <dcbw@redhat.com>
 */

#include <config.h>

#include <string.h>
#include <libsoup/soup.h>

#include "nm-connectivity.h"
#include "nm-logging.h"
#include "nm-manager.h"

G_DEFINE_TYPE (NMConnectivity, nm_connectivity, G_TYPE_OBJECT)

#define NM_CONNECTIVITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONNECTIVITY, NMConnectivityPrivate))


#define DEFAULT_RESPONSE "NetworkManager is online" /* NOT LOCALIZED */

typedef struct {
	/* used for http requests */
	SoupSession *soup_session;
	/* indicates if a connectivity check is currently running */
	gboolean running;
	/* the uri to check */
	char *uri;
	/* seconds when a check will be repeated */
	guint interval;
	/* the expected response for the connectivity check */
	char *response;
	/* indicates if the last connection check was successful */
	gboolean connected;
	/* the source id for the periodic check */
	guint check_id;
} NMConnectivityPrivate;

enum {
	PROP_0,
	PROP_RUNNING,
	PROP_URI,
	PROP_INTERVAL,
	PROP_RESPONSE,
	PROP_CONNECTED,
	LAST_PROP
};


gboolean
nm_connectivity_get_connected (NMConnectivity *connectivity)
{
	g_return_val_if_fail (NM_IS_CONNECTIVITY (connectivity), FALSE);

	return NM_CONNECTIVITY_GET_PRIVATE (connectivity)->connected;
}

static void
update_connected (NMConnectivity *self, gboolean connected)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	gboolean old_connected = priv->connected;

	if (priv->uri == NULL || priv->interval == 0) {
		/* Default to connected if no checks are to be run */
		priv->connected = TRUE;
	} else
		priv->connected = connected;

	if (priv->connected != old_connected)
		g_object_notify (G_OBJECT (self), NM_CONNECTIVITY_CONNECTED);
}

static void
nm_connectivity_check_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (user_data);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	SoupURI *soup_uri;
	gboolean connected_new = FALSE;
	const char *nm_header;
	char *uri_string;

	soup_uri = soup_message_get_uri (msg);
	uri_string = soup_uri_to_string (soup_uri, FALSE);

	/* Check headers; if we find the NM-specific one we're done */
	nm_header = soup_message_headers_get_one (msg->response_headers, "X-NetworkManager-Status");
	if (g_strcmp0 (nm_header, "online") == 0) {
		nm_log_dbg (LOGD_CORE, "Connectivity check for uri '%s' with Status header successful.", uri_string);
		connected_new = TRUE;
	} else {
		/* check response */
		if (msg->response_body->data &&	(g_str_has_prefix (msg->response_body->data, priv->response))) {
			nm_log_dbg (LOGD_CORE, "Connectivity check for uri '%s' with expected response '%s' successful.",
				        uri_string, priv->response);
			connected_new = TRUE;
		} else {
			nm_log_dbg (LOGD_CORE, "Connectivity check for uri '%s' with expected response '%s' failed (status %d).",
						uri_string, priv->response, msg->status_code);
		}
	}
	g_free (uri_string);

	/* update connectivity and emit signal */
	update_connected (self, connected_new);

	priv->running = FALSE;
	g_object_notify (G_OBJECT (self), NM_CONNECTIVITY_RUNNING);
}

static gboolean
run_check (gpointer user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (user_data);
	NMConnectivityPrivate *priv;
	SoupURI *soup_uri;
	SoupMessage *msg;

	g_return_val_if_fail (NM_IS_CONNECTIVITY (self), FALSE);
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	/* check given url async */
	soup_uri = soup_uri_new (priv->uri);
	if (soup_uri && SOUP_URI_VALID_FOR_HTTP (soup_uri)) {
		msg = soup_message_new_from_uri ("GET", soup_uri);
		soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
		soup_session_queue_message (priv->soup_session,
		                            msg,
		                            nm_connectivity_check_cb,
		                            self);

		priv->running = TRUE;
		g_object_notify (G_OBJECT (self), NM_CONNECTIVITY_RUNNING);
		nm_log_dbg (LOGD_CORE, "Connectivity check with uri '%s' started.", priv->uri);
	} else
		nm_log_err (LOGD_CORE, "Invalid uri '%s' for connectivity check.", priv->uri);

	if (soup_uri)
		soup_uri_free (soup_uri);

	return TRUE;  /* keep firing */
}

void
nm_connectivity_start_check (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (!priv->uri || !priv->interval) {
		nm_connectivity_stop_check (self);
		return;
	}

	if (priv->check_id == 0)
		priv->check_id = g_timeout_add_seconds (priv->interval, run_check, self);

	/* Start an immediate check */
	if (priv->running == FALSE)
		run_check (self);
}

void
nm_connectivity_stop_check (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (priv->check_id) {
		g_source_remove (priv->check_id);
		priv->check_id = 0;
	}

	update_connected (self, FALSE);
}

NMConnectivity *
nm_connectivity_new (const gchar *check_uri,
                     guint check_interval,
                     const gchar *check_response)
{
	NMConnectivity *self;

	self = g_object_new (NM_TYPE_CONNECTIVITY,
	                     NM_CONNECTIVITY_URI, check_uri,
	                     NM_CONNECTIVITY_INTERVAL, check_interval,
	                     NM_CONNECTIVITY_RESPONSE, check_response ? check_response : DEFAULT_RESPONSE,
	                     NULL);
	g_return_val_if_fail (self != NULL, NULL);
	update_connected (self, FALSE);

	return self;
}

static char *
sanitize_string_val (const GValue *val)
{
	char *s;

	/* Return NULL if string is NULL or zero-length */
	s = g_value_dup_string (val);
	if (!s || !s[0]) {
		g_free (s);
		return NULL;
	}
	return s;
}

static void
set_property (GObject *object, guint property_id,
              const GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	switch (property_id) {
	case PROP_RUNNING:
		priv->running = g_value_get_boolean (value);
		break;
	case PROP_URI:
		g_free (priv->uri);
		priv->uri = sanitize_string_val (value);
		break;
	case PROP_INTERVAL:
		priv->interval = g_value_get_uint (value);
		break;
	case PROP_RESPONSE:
		g_free (priv->response);
		priv->response = sanitize_string_val (value);
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
get_property (GObject *object, guint property_id,
              GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	switch (property_id) {
	case PROP_RUNNING:
		g_value_set_boolean (value, priv->running);
		break;
	case PROP_URI:
		g_value_set_string (value, priv->uri);
		break;
	case PROP_INTERVAL:
		g_value_set_uint (value, priv->interval);
		break;
	case PROP_RESPONSE:
		g_value_set_string (value, priv->response);
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

	priv->soup_session = soup_session_async_new_with_options (SOUP_SESSION_TIMEOUT, 15, NULL);
}


static void
dispose (GObject *object)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (priv->soup_session) {
		soup_session_abort (priv->soup_session);
		g_object_unref (priv->soup_session);
		priv->soup_session = NULL;
	}

	g_free (priv->uri);
	g_free (priv->response);

	if (priv->check_id > 0) {
		g_source_remove (priv->check_id);
		priv->check_id = 0;
	}
}


static void
nm_connectivity_class_init (NMConnectivityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	g_type_class_add_private (klass, sizeof (NMConnectivityPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_RUNNING,
		 g_param_spec_boolean (NM_CONNECTIVITY_RUNNING,
		                       "Running",
		                       "Connectivity check is running",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_URI,
		 g_param_spec_string (NM_CONNECTIVITY_URI,
		                      "URI",
		                      "Connectivity check URI",
		                      NULL,
		                      G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_INTERVAL,
		 g_param_spec_uint (NM_CONNECTIVITY_INTERVAL,
		                    "Interval",
		                    "Connectivity check interval in seconds",
		                    0, G_MAXUINT, 300,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_RESPONSE,
		 g_param_spec_string (NM_CONNECTIVITY_RESPONSE,
		                      "Response",
		                      "Expected connectivity check reponse",
		                      DEFAULT_RESPONSE,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_CONNECTED,
		 g_param_spec_boolean (NM_CONNECTIVITY_CONNECTED,
		                       "Connected",
		                       "Is connected",
		                       FALSE,
		                       G_PARAM_READABLE));
}

