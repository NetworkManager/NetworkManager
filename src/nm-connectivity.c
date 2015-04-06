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

#include "config.h"

#include <string.h>
#if WITH_CONCHECK
#include <libsoup/soup.h>
#endif


#include "nm-glib.h"
#include "nm-connectivity.h"
#include "nm-config.h"
#include "nm-logging.h"

G_DEFINE_TYPE (NMConnectivity, nm_connectivity, G_TYPE_OBJECT)

#define NM_CONNECTIVITY_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONNECTIVITY, NMConnectivityPrivate))


#define _LOG_DEFAULT_DOMAIN  LOGD_CONCHECK

#define _LOG(level, domain, ...) \
    G_STMT_START { \
        nm_log ((level), (domain), \
                "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                "connectivity: " \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

#define _LOGT(...)      _LOG (LOGL_TRACE, _LOG_DEFAULT_DOMAIN, __VA_ARGS__)
#define _LOGD(...)      _LOG (LOGL_DEBUG, _LOG_DEFAULT_DOMAIN, __VA_ARGS__)
#define _LOGI(...)      _LOG (LOGL_INFO,  _LOG_DEFAULT_DOMAIN, __VA_ARGS__)
#define _LOGW(...)      _LOG (LOGL_WARN,  _LOG_DEFAULT_DOMAIN, __VA_ARGS__)
#define _LOGE(...)      _LOG (LOGL_ERR,   _LOG_DEFAULT_DOMAIN, __VA_ARGS__)


typedef struct {
	char *uri;
	char *response;
	guint interval;
	gboolean online; /* whether periodic connectivity checking is enabled. */

#if WITH_CONCHECK
	SoupSession *soup_session;
	gboolean initial_check_obsoleted;
	guint check_id;
#endif

	NMConnectivityState state;
} NMConnectivityPrivate;

enum {
	PROP_0,
	PROP_URI,
	PROP_INTERVAL,
	PROP_RESPONSE,
	PROP_STATE,
	LAST_PROP
};


NMConnectivityState
nm_connectivity_get_state (NMConnectivity *connectivity)
{
	g_return_val_if_fail (NM_IS_CONNECTIVITY (connectivity), NM_CONNECTIVITY_UNKNOWN);

	return NM_CONNECTIVITY_GET_PRIVATE (connectivity)->state;
}

const char *
nm_connectivity_state_to_string (NMConnectivityState state)
{
	switch (state) {
	case NM_CONNECTIVITY_UNKNOWN:
		return "UNKNOWN";
	case NM_CONNECTIVITY_NONE:
		return "NONE";
	case NM_CONNECTIVITY_LIMITED:
		return "LIMITED";
	case NM_CONNECTIVITY_PORTAL:
		return "PORTAL";
	case NM_CONNECTIVITY_FULL:
		return "FULL";
	default:
		g_return_val_if_reached ("???");
	}
}

static void
update_state (NMConnectivity *self, NMConnectivityState state)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (priv->state != state) {
		_LOGD ("state changed from %s to %s",
		       nm_connectivity_state_to_string (priv->state),
		       nm_connectivity_state_to_string (state));
		priv->state = state;
		g_object_notify (G_OBJECT (self), NM_CONNECTIVITY_STATE);
	}
}

#if WITH_CONCHECK
typedef struct {
	GSimpleAsyncResult *simple;
	char *uri;
	char *response;
	guint check_id_when_scheduled;
} ConCheckCbData;

static void
nm_connectivity_check_cb (SoupSession *session, SoupMessage *msg, gpointer user_data)
{
	NMConnectivity *self;
	NMConnectivityPrivate *priv;
	ConCheckCbData *cb_data = user_data;
	GSimpleAsyncResult *simple = cb_data->simple;
	NMConnectivityState new_state;
	const char *nm_header;
	const char *uri = cb_data->uri;
	const char *response = cb_data->response ? cb_data->response : NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE;

	self = NM_CONNECTIVITY (g_async_result_get_source_object (G_ASYNC_RESULT (simple)));
	/* it is safe to unref @self here, @simple holds yet another reference. */
	g_object_unref (self);
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (SOUP_STATUS_IS_TRANSPORT_ERROR (msg->status_code)) {
		_LOGI ("check for uri '%s' failed with '%s'", uri, msg->reason_phrase);
		new_state = NM_CONNECTIVITY_LIMITED;
		goto done;
	}

	if (msg->status_code == 511) {
		_LOGD ("check for uri '%s' returned status '%d %s'; captive portal present.",
			   uri, msg->status_code, msg->reason_phrase);
		new_state = NM_CONNECTIVITY_PORTAL;
	} else {
		/* Check headers; if we find the NM-specific one we're done */
		nm_header = soup_message_headers_get_one (msg->response_headers, "X-NetworkManager-Status");
		if (g_strcmp0 (nm_header, "online") == 0) {
			_LOGD ("check for uri '%s' with Status header successful.", uri);
			new_state = NM_CONNECTIVITY_FULL;
		} else if (msg->status_code == SOUP_STATUS_OK) {
			/* check response */
			if (msg->response_body->data && g_str_has_prefix (msg->response_body->data, response)) {
				_LOGD ("check for uri '%s' successful.", uri);
				new_state = NM_CONNECTIVITY_FULL;
			} else {
				_LOGI ("check for uri '%s' did not match expected response '%s'; assuming captive portal.",
					   uri, response);
				new_state = NM_CONNECTIVITY_PORTAL;
			}
		} else {
			_LOGI ("check for uri '%s' returned status '%d %s'; assuming captive portal.",
				   uri, msg->status_code, msg->reason_phrase);
			new_state = NM_CONNECTIVITY_PORTAL;
		}
	}

 done:
	/* Only update the state, if the call was done from external, or if the periodic check
	 * is still the one that called this async check. */
	if (!cb_data->check_id_when_scheduled || cb_data->check_id_when_scheduled == priv->check_id) {
		/* Only update the state, if the URI and response parameters did not change
		 * since invocation.
		 * The interval does not matter for exernal calls, and for internal calls
		 * we don't reach this line if the interval changed. */
		if (   !g_strcmp0 (cb_data->uri, priv->uri)
		    && !g_strcmp0 (cb_data->response, priv->response))
			update_state (self, new_state);
	}

	g_simple_async_result_set_op_res_gssize (simple, new_state);
	g_simple_async_result_complete (simple);
	g_object_unref (simple);

	g_free (cb_data->uri);
	g_free (cb_data->response);
	g_slice_free (ConCheckCbData, cb_data);
}

#define IS_PERIODIC_CHECK(callback)  (callback == run_check_complete)

static void
run_check_complete (GObject      *object,
                    GAsyncResult *result,
                    gpointer      user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	GError *error = NULL;

	nm_connectivity_check_finish (self, result, &error);
	if (error) {
		_LOGE ("check failed: %s", error->message);
		g_error_free (error);
	}
}

static gboolean
run_check (gpointer user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (user_data);

	nm_connectivity_check_async (self, run_check_complete, NULL);
	return TRUE;
}

static gboolean
idle_start_periodic_checks (gpointer user_data)
{
	NMConnectivity *self = user_data;
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	priv->check_id = g_timeout_add_seconds (priv->interval, run_check, self);
	if (!priv->initial_check_obsoleted)
		run_check (self);

	return FALSE;
}
#endif

static void
_reschedule_periodic_checks (NMConnectivity *self, gboolean force_reschedule)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

#if WITH_CONCHECK
	if (priv->online && priv->uri && priv->interval) {
		if (force_reschedule || !priv->check_id) {
			if (priv->check_id)
				g_source_remove (priv->check_id);
			priv->check_id = g_timeout_add (0, idle_start_periodic_checks, self);
			priv->initial_check_obsoleted = FALSE;
		}
	} else {
		if (priv->check_id) {
			g_source_remove (priv->check_id);
			priv->check_id = 0;
		}
	}
	if (priv->check_id)
		return;
#endif

	/* Either @online is %TRUE but we aren't checking connectivity, or
	 * @online is %FALSE. Either way we can update our status immediately.
	 */
	update_state (self, priv->online ? NM_CONNECTIVITY_FULL : NM_CONNECTIVITY_NONE);
}

void
nm_connectivity_set_online (NMConnectivity *self,
                            gboolean        online)
{
	NMConnectivityPrivate *priv= NM_CONNECTIVITY_GET_PRIVATE (self);

	online = !!online;
	if (priv->online != online) {
		_LOGD ("set %s", online ? "online" : "offline");
		priv->online = online;
		_reschedule_periodic_checks (self, FALSE);
	}
}

void
nm_connectivity_check_async (NMConnectivity      *self,
                             GAsyncReadyCallback  callback,
                             gpointer             user_data)
{
	NMConnectivityPrivate *priv;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_CONNECTIVITY (self));
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	simple = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                    nm_connectivity_check_async);

#if WITH_CONCHECK
	if (priv->uri && priv->interval) {
		SoupMessage *msg;
		ConCheckCbData *cb_data = g_slice_new (ConCheckCbData);

		msg = soup_message_new ("GET", priv->uri);
		soup_message_set_flags (msg, SOUP_MESSAGE_NO_REDIRECT);
		/* Disable HTTP/1.1 keepalive; the connection should not persist */
		soup_message_headers_append (msg->request_headers, "Connection", "close");
		cb_data->simple = simple;
		cb_data->uri = g_strdup (priv->uri);
		cb_data->response = g_strdup (priv->response);

		/* For internal calls (periodic), remember the check-id at time of scheduling. */
		cb_data->check_id_when_scheduled = IS_PERIODIC_CHECK (callback) ? priv->check_id : 0;

		soup_session_queue_message (priv->soup_session,
		                            msg,
		                            nm_connectivity_check_cb,
		                            cb_data);
		priv->initial_check_obsoleted = TRUE;

		_LOGD ("check: send %srequest to '%s'", IS_PERIODIC_CHECK (callback) ? "periodic " : "", priv->uri);
		return;
	} else {
		g_warn_if_fail (!IS_PERIODIC_CHECK (callback));
		_LOGD ("check: faking request. Connectivity check disabled");
	}
#else
	_LOGD ("check: faking request. Compiled without connectivity-check support");
#endif

	g_simple_async_result_set_op_res_gssize (simple, priv->state);
	g_simple_async_result_complete_in_idle (simple);
	g_object_unref (simple);
}

NMConnectivityState
nm_connectivity_check_finish (NMConnectivity  *self,
                              GAsyncResult    *result,
                              GError         **error)
{
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (self), nm_connectivity_check_async), NM_CONNECTIVITY_UNKNOWN);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NM_CONNECTIVITY_UNKNOWN;
	return (NMConnectivityState) g_simple_async_result_get_op_res_gssize (simple);
}

/**************************************************************************/

NMConnectivity *
nm_connectivity_new (const char *uri,
                     guint interval,
                     const char *response)
{
	return g_object_new (NM_TYPE_CONNECTIVITY,
	                     NM_CONNECTIVITY_URI, uri,
	                     NM_CONNECTIVITY_INTERVAL, interval,
	                     NM_CONNECTIVITY_RESPONSE, response,
	                     NULL);
}

static void
set_property (GObject *object, guint property_id,
              const GValue *value, GParamSpec *pspec)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	const char *uri, *response;
	guint interval;
	gboolean changed;

	switch (property_id) {
	case PROP_URI:
		uri = g_value_get_string (value);
		if (uri && !*uri)
			uri = NULL;
		changed = g_strcmp0 (uri, priv->uri) != 0;
#if WITH_CONCHECK
		if (uri) {
			SoupURI *soup_uri = soup_uri_new (uri);

			if (!soup_uri || !SOUP_URI_VALID_FOR_HTTP (soup_uri)) {
				_LOGE ("invalid uri '%s' for connectivity check.", uri);
				uri = NULL;
			}
			if (uri && soup_uri && changed &&
			    soup_uri_get_scheme(soup_uri) == SOUP_URI_SCHEME_HTTPS)
				_LOGW ("use of HTTPS for connectivity checking is not reliable and is discouraged (URI: %s)", uri);
			if (soup_uri)
				soup_uri_free (soup_uri);
		}
#endif
		if (changed) {
			g_free (priv->uri);
			priv->uri = g_strdup (uri);
			_reschedule_periodic_checks (self, TRUE);
		}
		break;
	case PROP_INTERVAL:
		interval = g_value_get_uint (value);
		if (priv->interval != interval) {
			priv->interval = interval;
			_reschedule_periodic_checks (self, TRUE);
		}
		break;
	case PROP_RESPONSE:
		response = g_value_get_string (value);
		if (g_strcmp0 (response, priv->response) != 0) {
			/* a response %NULL means, NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE. Any other response
			 * (including "") is accepted. */
			g_free (priv->response);
			priv->response = g_strdup (response);
			_reschedule_periodic_checks (self, TRUE);
		}
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
	case PROP_URI:
		g_value_set_string (value, priv->uri);
		break;
	case PROP_INTERVAL:
		g_value_set_uint (value, priv->interval);
		break;
	case PROP_RESPONSE:
		if (priv->response)
			g_value_set_string (value, priv->response);
		else
			g_value_set_static_string (value, NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE);
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
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

#if WITH_CONCHECK
	priv->soup_session = soup_session_async_new_with_options (SOUP_SESSION_TIMEOUT, 15, NULL);
#endif
	priv->state = NM_CONNECTIVITY_NONE;
}


static void
dispose (GObject *object)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	g_clear_pointer (&priv->uri, g_free);
	g_clear_pointer (&priv->response, g_free);

#if WITH_CONCHECK
	if (priv->soup_session) {
		soup_session_abort (priv->soup_session);
		g_clear_object (&priv->soup_session);
	}

	if (priv->check_id > 0) {
		g_source_remove (priv->check_id);
		priv->check_id = 0;
	}
#endif
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
	    (object_class, PROP_URI,
	     g_param_spec_string (NM_CONNECTIVITY_URI, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_INTERVAL,
	     g_param_spec_uint (NM_CONNECTIVITY_INTERVAL, "", "",
	                        0, G_MAXUINT, NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT |
	                        G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_RESPONSE,
	     g_param_spec_string (NM_CONNECTIVITY_RESPONSE, "", "",
	                          NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
	    (object_class, PROP_STATE,
	     g_param_spec_uint (NM_CONNECTIVITY_STATE, "", "",
	                        NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS));
}

