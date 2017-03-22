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
 * Copyright (C) 2016,2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-connectivity.h"

#include <string.h>
#if WITH_CONCHECK
#include <curl/curl.h>
#endif

#include "nm-config.h"
#include "nm-dispatcher.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMConnectivity,
	PROP_URI,
	PROP_INTERVAL,
	PROP_RESPONSE,
	PROP_STATE,
);

typedef struct {
	char *uri;
	char *response;
	guint interval;
	gboolean online; /* whether periodic connectivity checking is enabled. */

#if WITH_CONCHECK
	CURLM *curl_mhandle;
	guint curl_timer;
	gboolean initial_check_obsoleted;
	guint check_id;
#endif

	NMConnectivityState state;
} NMConnectivityPrivate;

struct _NMConnectivity {
	GObject parent;
	NMConnectivityPrivate _priv;
};

struct _NMConnectivityClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMConnectivity, nm_connectivity, G_TYPE_OBJECT)

#define NM_CONNECTIVITY_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMConnectivity, NM_IS_CONNECTIVITY)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CONCHECK
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "connectivity", __VA_ARGS__)

/*****************************************************************************/

NMConnectivityState
nm_connectivity_get_state (NMConnectivity *connectivity)
{
	g_return_val_if_fail (NM_IS_CONNECTIVITY (connectivity), NM_CONNECTIVITY_UNKNOWN);

	return NM_CONNECTIVITY_GET_PRIVATE (connectivity)->state;
}

NM_UTILS_LOOKUP_STR_DEFINE (nm_connectivity_state_to_string, NMConnectivityState,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("???"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_UNKNOWN,  "UNKNOWN"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_NONE,     "NONE"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_LIMITED,  "LIMITED"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_PORTAL,   "PORTAL"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_FULL,     "FULL"),
);

static void
update_state (NMConnectivity *self, NMConnectivityState state)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	if (priv->state != state) {
		_LOGD ("state changed from %s to %s",
		       nm_connectivity_state_to_string (priv->state),
		       nm_connectivity_state_to_string (state));
		priv->state = state;
		_notify (self, PROP_STATE);

		nm_dispatcher_call_connectivity (state, NULL, NULL, NULL);
	}
}

/*****************************************************************************/

#if WITH_CONCHECK
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
		nm_clear_g_source (&priv->check_id);
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

/*****************************************************************************/

#if WITH_CONCHECK
typedef struct {
	GSimpleAsyncResult *simple;
	char *uri;
	char *response;
	guint check_id_when_scheduled;
	CURL *curl_ehandle;
	size_t msg_size;
	char *msg;
	struct curl_slist *request_headers;
	guint timeout_id;
} ConCheckCbData;

static void
finish_cb_data (ConCheckCbData *cb_data, NMConnectivityState new_state)
{
	NMConnectivity *self = NM_CONNECTIVITY (g_async_result_get_source_object (G_ASYNC_RESULT (cb_data->simple)));
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	/* Only update the state, if the call was done from external, or if the periodic check
	 * is still the one that called this async check. */
	if (!cb_data->check_id_when_scheduled || cb_data->check_id_when_scheduled == priv->check_id) {
		/* Only update the state, if the URI and response parameters did not change
		 * since invocation.
		 * The interval does not matter for exernal calls, and for internal calls
		 * we don't reach this line if the interval changed. */
		if (   !g_strcmp0 (cb_data->uri, priv->uri)
		    && !g_strcmp0 (cb_data->response, priv->response)) {
			_LOGT ("Update to connectivity state %s",
			       nm_connectivity_state_to_string (new_state));
			update_state (self, new_state);
		}
	}

	/* Contrary to what cURL manual claim it is *not* safe to remove
	 * the easy handle "at any moment"; specifically not from the
	 * write function. Thus here we just dissociate the cb_data from
	 * the easy handle and the easy handle will be cleaned up when the
	 * message goes to CURLMSG_DONE in curl_check_connectivity(). */
	curl_easy_setopt (cb_data->curl_ehandle, CURLOPT_PRIVATE, NULL);

	g_simple_async_result_set_op_res_gssize (cb_data->simple, new_state);
	g_simple_async_result_complete (cb_data->simple);
	g_object_unref (cb_data->simple);
	curl_slist_free_all (cb_data->request_headers);
	g_free (cb_data->uri);
	g_free (cb_data->response);
	g_source_remove (cb_data->timeout_id);
	g_slice_free (ConCheckCbData, cb_data);
}

static void
curl_check_connectivity (CURLM *mhandle, CURLMcode ret)
{
	ConCheckCbData *cb_data;
	CURLMsg *msg;
	CURLcode eret;
	gint m_left;

	_LOGT ("curl_multi check for easy messages");
	if (ret != CURLM_OK)
		_LOGE ("Connectivity check failed");

	while ((msg = curl_multi_info_read (mhandle, &m_left))) {
		_LOGT ("curl MSG received - ehandle:%p, type:%d", msg->easy_handle, msg->msg);
		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Here we have completed a session. Check easy session result. */
		eret = curl_easy_getinfo (msg->easy_handle, CURLINFO_PRIVATE, &cb_data);
		if (eret != CURLE_OK) {
			_LOGE ("curl cannot extract cb_data for easy handle %p, skipping msg", msg->easy_handle);
			continue;
		}

		if (cb_data) {
			/* If cb_data is still there this message hasn't been
			 * taken care of. Do so now. */
			if (msg->data.result == CURLE_OK) {
				/* If we get here, it means that easy_write_cb() didn't read enough
				 * bytes to be able to do a match. */
				_LOGI ("Check for uri '%s' returned a shorter response than expected '%s'; assuming captive portal.",
				       cb_data->uri, cb_data->response);
				finish_cb_data (cb_data, NM_CONNECTIVITY_PORTAL);
			} else {
				_LOGD ("Check for uri '%s' failed", cb_data->uri);
				finish_cb_data (cb_data, NM_CONNECTIVITY_LIMITED);
			}
		}

		curl_multi_remove_handle (mhandle, msg->easy_handle);
		curl_easy_cleanup (msg->easy_handle);
	}
}

static gboolean
curl_timeout_cb (gpointer user_data)
{
	NMConnectivity *self = NM_CONNECTIVITY (user_data);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	CURLMcode ret;
	int pending_conn;

	priv->curl_timer = 0;

	ret = curl_multi_socket_action (priv->curl_mhandle, CURL_SOCKET_TIMEOUT, 0, &pending_conn);
	_LOGT ("timeout elapsed - multi_socket_action (%d conn remaining)", pending_conn);

	curl_check_connectivity (priv->curl_mhandle, ret);

	return G_SOURCE_REMOVE;
}

static int
multi_timer_cb (CURLM *multi, long timeout_ms, void *userdata)
{
	NMConnectivity *self = NM_CONNECTIVITY (userdata);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	_LOGT ("curl_multi timer invocation --> timeout ms: %ld", timeout_ms);

	nm_clear_g_source (&priv->curl_timer);
	if (timeout_ms != -1)
		priv->curl_timer = g_timeout_add (timeout_ms * 1000, curl_timeout_cb, self);

	return 0;
}

static gboolean
curl_socketevent_cb (GIOChannel *ch, GIOCondition condition, gpointer data)
{
	NMConnectivity *self = NM_CONNECTIVITY (data);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	CURLMcode ret;
	int pending_conn = 0;
	gboolean bret = TRUE;
	int fd = g_io_channel_unix_get_fd (ch);
	int action = 0;

	if (condition & G_IO_IN)
		action |= CURL_CSELECT_IN;
	if (condition & G_IO_OUT)
		action |= CURL_CSELECT_OUT;

	ret = curl_multi_socket_action (priv->curl_mhandle, fd, 0, &pending_conn);
	_LOGT ("activity on monitored fd %d - multi_socket_action (%d conn remaining)", fd, pending_conn);

	curl_check_connectivity (priv->curl_mhandle, ret);

	if (pending_conn == 0) {
		nm_clear_g_source (&priv->curl_timer);
		bret = FALSE;
	}
	return bret;
}

typedef struct {
	GIOChannel *ch;
	guint ev;
} CurlSockData;

static int
multi_socket_cb (CURL *e_handle, curl_socket_t s, int what, void *userdata, void *socketp)
{
	NMConnectivity *self = NM_CONNECTIVITY (userdata);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	CurlSockData *fdp = (CurlSockData *) socketp;
	GIOCondition condition = 0;

	_LOGT ("curl_multi socket callback --> socket %d", s);

	if (what == CURL_POLL_REMOVE) {
		if (fdp) {
			_LOGT ("remove socket s=%d", s);
			nm_clear_g_source (&fdp->ev);
			g_io_channel_unref (fdp->ch);
			g_slice_free (CurlSockData, fdp);
		}
	} else {
		if (!fdp) {
			_LOGT ("register new socket s=%d", s);
			fdp = g_slice_new0 (CurlSockData);
			fdp->ch = g_io_channel_unix_new (s);
		} else
			nm_clear_g_source (&fdp->ev);

		if (what & CURL_POLL_IN)
			condition |= G_IO_IN;
		if (what & CURL_POLL_OUT)
			condition |= G_IO_OUT;

		fdp->ev = g_io_add_watch (fdp->ch, condition, curl_socketevent_cb, self);
		curl_multi_assign (priv->curl_mhandle, s, fdp);
	}

	return CURLM_OK;
}

#define HEADER_STATUS_ONLINE "X-NetworkManager-Status: online\r\n"

static size_t
easy_header_cb (char *buffer, size_t size, size_t nitems, void *userdata)
{
	ConCheckCbData *cb_data = userdata;
	size_t len = size * nitems;

	_LOGT ("Received %lu header bytes from cURL\n", len);

	if (   len >= sizeof (HEADER_STATUS_ONLINE) - 1
	    && !g_ascii_strncasecmp (buffer, HEADER_STATUS_ONLINE, sizeof (HEADER_STATUS_ONLINE) - 1)) {
		_LOGD ("check for uri '%s' with Status header successful.", cb_data->uri);
		finish_cb_data (cb_data, NM_CONNECTIVITY_FULL);
		return 0;
	}

	return len;
}

static size_t
easy_write_cb (void *buffer, size_t size, size_t nmemb, void *userdata)
{
	ConCheckCbData *cb_data = userdata;
	size_t len = size * nmemb;

	_LOGT ("Received %lu body bytes from cURL\n", len);

	cb_data->msg = g_realloc (cb_data->msg, cb_data->msg_size + len);
	memcpy (cb_data->msg + cb_data->msg_size, buffer, len);
	cb_data->msg_size += len;

	if (cb_data->msg_size >= strlen (cb_data->response)) {
		/* We already have enough data -- check response */
		if (g_str_has_prefix (cb_data->msg, cb_data->response)) {
			_LOGD ("Check for uri '%s' successful.", cb_data->uri);
			finish_cb_data (cb_data, NM_CONNECTIVITY_FULL);
		} else {
			_LOGI ("Check for uri '%s' did not match expected response '%s'; assuming captive portal.",
			       cb_data->uri, cb_data->response);
			finish_cb_data (cb_data, NM_CONNECTIVITY_PORTAL);
		}
		return 0;
	}

	return len;
}

static gboolean
timeout_cb (gpointer user_data)
{
	ConCheckCbData *cb_data = user_data;
	NMConnectivity *self = NM_CONNECTIVITY (g_async_result_get_source_object (G_ASYNC_RESULT (cb_data->simple)));
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	CURL *ehandle = cb_data->curl_ehandle;

	_LOGI ("Check for uri '%s' timed out.", cb_data->uri);
	finish_cb_data (cb_data, NM_CONNECTIVITY_LIMITED);
	curl_multi_remove_handle (priv->curl_mhandle, ehandle);
	curl_easy_cleanup (ehandle);

	return G_SOURCE_REMOVE;
}
#endif

#define IS_PERIODIC_CHECK(callback)  ((callback) == run_check_complete)

void
nm_connectivity_check_async (NMConnectivity      *self,
                             GAsyncReadyCallback  callback,
                             gpointer             user_data)
{
	NMConnectivityPrivate *priv;
	GSimpleAsyncResult *simple;
#if WITH_CONCHECK
	CURL *ehandle = NULL;
#endif

	g_return_if_fail (NM_IS_CONNECTIVITY (self));
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	simple = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                    nm_connectivity_check_async);

#if WITH_CONCHECK
	if (priv->uri && priv->interval && priv->curl_mhandle)
		ehandle = curl_easy_init ();

	if (ehandle) {
		ConCheckCbData *cb_data = g_slice_new0 (ConCheckCbData);

		cb_data->curl_ehandle = ehandle;
		cb_data->request_headers = curl_slist_append (NULL, "Connection: close");
		cb_data->simple = simple;
		cb_data->uri = g_strdup (priv->uri);
		if (priv->response)
			cb_data->response = g_strdup (priv->response);
		else
			cb_data->response = g_strdup (NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE);

		/* For internal calls (periodic), remember the check-id at time of scheduling. */
		cb_data->check_id_when_scheduled = IS_PERIODIC_CHECK (callback) ? priv->check_id : 0;

		curl_easy_setopt (ehandle, CURLOPT_URL, priv->uri);
		curl_easy_setopt (ehandle, CURLOPT_WRITEFUNCTION, easy_write_cb);
		curl_easy_setopt (ehandle, CURLOPT_WRITEDATA, cb_data);
		curl_easy_setopt (ehandle, CURLOPT_HEADERFUNCTION, easy_header_cb);
		curl_easy_setopt (ehandle, CURLOPT_HEADERDATA, cb_data);
		curl_easy_setopt (ehandle, CURLOPT_PRIVATE, cb_data);
		curl_easy_setopt (ehandle, CURLOPT_HTTPHEADER, cb_data->request_headers);
		curl_multi_add_handle (priv->curl_mhandle, ehandle);

		cb_data->timeout_id = g_timeout_add_seconds (30, timeout_cb, cb_data);

		priv->initial_check_obsoleted = TRUE;

		_LOGD ("check: send %s request to '%s'", IS_PERIODIC_CHECK (callback) ? "periodic " : "", priv->uri);
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

/*****************************************************************************/

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
			char *scheme = g_uri_parse_scheme (uri);

			if (!scheme) {
				_LOGE ("invalid URI '%s' for connectivity check.", uri);
				uri = NULL;
			} else if (strcasecmp (scheme, "https") == 0) {
				_LOGW ("use of HTTPS for connectivity checking is not reliable and is discouraged (URI: %s)", uri);
			} else if (strcasecmp (scheme, "http") != 0) {
				_LOGE ("scheme of '%s' uri does't use a scheme that is allowed for connectivity check.", uri);
				uri = NULL;
			}

			if (scheme)
				g_free (scheme);
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

/*****************************************************************************/


static void
nm_connectivity_init (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
#if WITH_CONCHECK
	CURLcode retv;
#endif

	priv->state = NM_CONNECTIVITY_NONE;
#if WITH_CONCHECK
	retv = curl_global_init (CURL_GLOBAL_ALL);
	if (retv == CURLE_OK)
		priv->curl_mhandle = curl_multi_init ();

	if (priv->curl_mhandle == NULL) {
		 _LOGE ("Unable to init cURL, connectivity check will not work");
		return;
	}

	curl_multi_setopt (priv->curl_mhandle, CURLMOPT_SOCKETFUNCTION, multi_socket_cb);
	curl_multi_setopt (priv->curl_mhandle, CURLMOPT_SOCKETDATA, self);
	curl_multi_setopt (priv->curl_mhandle, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
	curl_multi_setopt (priv->curl_mhandle, CURLMOPT_TIMERDATA, self);
	curl_multi_setopt (priv->curl_mhandle, CURLOPT_VERBOSE, 1);
#endif
}

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
dispose (GObject *object)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	g_clear_pointer (&priv->uri, g_free);
	g_clear_pointer (&priv->response, g_free);

#if WITH_CONCHECK
	curl_multi_cleanup (priv->curl_mhandle);
	curl_global_cleanup ();

	nm_clear_g_source (&priv->check_id);
#endif

	G_OBJECT_CLASS (nm_connectivity_parent_class)->dispose (object);
}

static void
nm_connectivity_class_init (NMConnectivityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	obj_properties[PROP_URI] =
	     g_param_spec_string (NM_CONNECTIVITY_URI, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_INTERVAL] =
	     g_param_spec_uint (NM_CONNECTIVITY_INTERVAL, "", "",
	                        0, G_MAXUINT, NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL,
	                        G_PARAM_READWRITE |
	                        G_PARAM_CONSTRUCT |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_RESPONSE] =
	     g_param_spec_string (NM_CONNECTIVITY_RESPONSE, "", "",
	                          NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STATE] =
	     g_param_spec_uint (NM_CONNECTIVITY_STATE, "", "",
	                        NM_CONNECTIVITY_UNKNOWN, NM_CONNECTIVITY_FULL, NM_CONNECTIVITY_UNKNOWN,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
