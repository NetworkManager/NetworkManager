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
#include <curl/curl.h>

#include "nm-config.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

typedef struct {
	char *uri;
	char *response;
	gboolean enabled;
	guint interval;
	NMConfig *config;
	guint periodic_check_id;
	CURLM *curl_mhandle;
	guint curl_timer;
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

NM_DEFINE_SINGLETON_GETTER (NMConnectivity, nm_connectivity_get, NM_TYPE_CONNECTIVITY);

enum {
	PERIODIC_CHECK,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CONCHECK
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "connectivity", __VA_ARGS__)

#define _NMLOG2_DOMAIN     LOGD_CONCHECK
#define _NMLOG2(level, ...) \
    G_STMT_START { \
        const NMLogLevel __level = (level); \
        \
        if (nm_logging_enabled (__level, _NMLOG2_DOMAIN)) { \
            _nm_log (__level, _NMLOG2_DOMAIN, 0, \
                        &cb_data->ifspec[3], NULL, \
                        "connectivity: (%s) " \
                        _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                        &cb_data->ifspec[3] \
                        _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE (nm_connectivity_state_to_string, NMConnectivityState,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("???"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_UNKNOWN,  "UNKNOWN"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_NONE,     "NONE"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_LIMITED,  "LIMITED"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_PORTAL,   "PORTAL"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_FULL,     "FULL"),
);

/*****************************************************************************/

typedef struct {
	GSimpleAsyncResult *simple;
	char *response;
	CURL *curl_ehandle;
	size_t msg_size;
	char *msg;
	struct curl_slist *request_headers;
	guint timeout_id;
	char *ifspec;
} ConCheckCbData;

static void
finish_cb_data (ConCheckCbData *cb_data, NMConnectivityState new_state)
{
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
	g_free (cb_data->response);
	g_free (cb_data->msg);
	g_free (cb_data->ifspec);
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

	if (ret != CURLM_OK)
		_LOGW ("connectivity check failed");

	while ((msg = curl_multi_info_read (mhandle, &m_left))) {
		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Here we have completed a session. Check easy session result. */
		eret = curl_easy_getinfo (msg->easy_handle, CURLINFO_PRIVATE, (char **) &cb_data);
		if (eret != CURLE_OK) {
			_LOG2E ("curl cannot extract cb_data for easy handle %p, skipping msg", msg->easy_handle);
			continue;
		}

		if (cb_data) {
			/* If cb_data is still there this message hasn't been
			 * taken care of. Do so now. */
			if (msg->data.result == CURLE_OK) {
				/* If we get here, it means that easy_write_cb() didn't read enough
				 * bytes to be able to do a match. */
				_LOG2I ("response shorter than expected '%s'; assuming captive portal.",
				        cb_data->response);
				finish_cb_data (cb_data, NM_CONNECTIVITY_PORTAL);
			} else {
				_LOG2D ("check failed (%d)", msg->data.result);
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

	if (what == CURL_POLL_REMOVE) {
		if (fdp) {
			nm_clear_g_source (&fdp->ev);
			g_io_channel_unref (fdp->ch);
			g_slice_free (CurlSockData, fdp);
		}
	} else {
		if (!fdp) {
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

	if (   len >= sizeof (HEADER_STATUS_ONLINE) - 1
	    && !g_ascii_strncasecmp (buffer, HEADER_STATUS_ONLINE, sizeof (HEADER_STATUS_ONLINE) - 1)) {
		_LOG2D ("status header found, check successful");
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

	cb_data->msg = g_realloc (cb_data->msg, cb_data->msg_size + len);
	memcpy (cb_data->msg + cb_data->msg_size, buffer, len);
	cb_data->msg_size += len;

	if (cb_data->msg_size >= strlen (cb_data->response)) {
		/* We already have enough data -- check response */
		if (g_str_has_prefix (cb_data->msg, cb_data->response)) {
			_LOG2D ("check successful.");
			finish_cb_data (cb_data, NM_CONNECTIVITY_FULL);
		} else {
			_LOG2I ("response did not match expected response '%s'; assuming captive portal.",
			        cb_data->response);
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

	_LOG2I ("timed out");
	finish_cb_data (cb_data, NM_CONNECTIVITY_LIMITED);
	curl_multi_remove_handle (priv->curl_mhandle, ehandle);
	curl_easy_cleanup (ehandle);

	return G_SOURCE_REMOVE;
}

void
nm_connectivity_check_async (NMConnectivity      *self,
                             const char          *iface,
                             GAsyncReadyCallback  callback,
                             gpointer             user_data)
{
	NMConnectivityPrivate *priv;
	GSimpleAsyncResult *simple;
	CURL *ehandle = NULL;

	g_return_if_fail (NM_IS_CONNECTIVITY (self));
	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	simple = g_simple_async_result_new (G_OBJECT (self), callback, user_data,
	                                    nm_connectivity_check_async);

	if (priv->enabled)
		ehandle = curl_easy_init ();

	if (ehandle) {
		ConCheckCbData *cb_data = g_slice_new0 (ConCheckCbData);

		cb_data->curl_ehandle = ehandle;
		cb_data->request_headers = curl_slist_append (NULL, "Connection: close");
		cb_data->ifspec = g_strdup_printf ("if!%s", iface);
		cb_data->simple = simple;
		if (priv->response)
			cb_data->response = g_strdup (priv->response);
		else
			cb_data->response = g_strdup (NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE);

		curl_easy_setopt (ehandle, CURLOPT_URL, priv->uri);
		curl_easy_setopt (ehandle, CURLOPT_WRITEFUNCTION, easy_write_cb);
		curl_easy_setopt (ehandle, CURLOPT_WRITEDATA, cb_data);
		curl_easy_setopt (ehandle, CURLOPT_HEADERFUNCTION, easy_header_cb);
		curl_easy_setopt (ehandle, CURLOPT_HEADERDATA, cb_data);
		curl_easy_setopt (ehandle, CURLOPT_PRIVATE, cb_data);
		curl_easy_setopt (ehandle, CURLOPT_HTTPHEADER, cb_data->request_headers);
		curl_easy_setopt (ehandle, CURLOPT_INTERFACE, cb_data->ifspec);
		curl_multi_add_handle (priv->curl_mhandle, ehandle);

		cb_data->timeout_id = g_timeout_add_seconds (30, timeout_cb, cb_data);

		_LOG2D ("sending request to '%s'", priv->uri);
		return;
	} else {
		_LOGD ("(%s) faking request. Connectivity check disabled", iface);
	}

	g_simple_async_result_set_op_res_gssize (simple, NM_CONNECTIVITY_UNKNOWN);
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

gboolean
nm_connectivity_check_enabled (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	return priv->enabled;
}

/*****************************************************************************/

static gboolean
periodic_check (gpointer user_data)
{
	g_signal_emit (NM_CONNECTIVITY (user_data), signals[PERIODIC_CHECK], 0);
	return G_SOURCE_CONTINUE;
}

static void
update_config (NMConnectivity *self, NMConfigData *config_data)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	const char *uri, *response;
	guint interval;
	gboolean enabled;
	gboolean changed = FALSE;

	/* Set the URI. */
	uri = nm_config_data_get_connectivity_uri (config_data);
	if (uri && !*uri)
		uri = NULL;
	changed = g_strcmp0 (uri, priv->uri) != 0;
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
	if (changed) {
		g_free (priv->uri);
		priv->uri = g_strdup (uri);
	}

	/* Set the interval. */
	interval = nm_config_data_get_connectivity_interval (config_data);
	if (priv->interval != interval) {
		priv->interval = interval;
		changed = TRUE;
	}

	/* Set enabled flag. */
	enabled = nm_config_data_get_connectivity_enabled (config_data);
	/* connectivity checking also requires a valid URI, interval and
	 * curl_mhandle */
	if (!(priv->uri && priv->interval && priv->curl_mhandle)) {
		enabled = FALSE;
	}
	if (priv->enabled != enabled) {
		priv->enabled = enabled;
		changed = TRUE;
	}

	/* Set the response. */
	response = nm_config_data_get_connectivity_response (config_data);
	if (g_strcmp0 (response, priv->response) != 0) {
		/* a response %NULL means, NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE. Any other response
		 * (including "") is accepted. */
		g_free (priv->response);
		priv->response = g_strdup (response);
		changed = TRUE;
	}

	if (changed) {
		nm_clear_g_source (&priv->periodic_check_id);
		if (nm_connectivity_check_enabled (self))
			priv->periodic_check_id = g_timeout_add_seconds (priv->interval, periodic_check, self);
	}
}

static void
config_changed_cb (NMConfig *config,
                   NMConfigData *config_data,
                   NMConfigChangeFlags changes,
                   NMConfigData *old_data,
                   NMConnectivity *self)
{
	update_config (self, config_data);
}

static void
nm_connectivity_init (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	CURLcode retv;

	retv = curl_global_init (CURL_GLOBAL_ALL);
	if (retv == CURLE_OK)
		priv->curl_mhandle = curl_multi_init ();

	if (!priv->curl_mhandle)
		 _LOGE ("unable to init cURL, connectivity check will not work");
	else {
		curl_multi_setopt (priv->curl_mhandle, CURLMOPT_SOCKETFUNCTION, multi_socket_cb);
		curl_multi_setopt (priv->curl_mhandle, CURLMOPT_SOCKETDATA, self);
		curl_multi_setopt (priv->curl_mhandle, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
		curl_multi_setopt (priv->curl_mhandle, CURLMOPT_TIMERDATA, self);
		curl_multi_setopt (priv->curl_mhandle, CURLOPT_VERBOSE, 1);
	}

	priv->config = g_object_ref (nm_config_get ());

	update_config (self, nm_config_get_data (priv->config));
	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  self);

}

static void
dispose (GObject *object)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	g_clear_pointer (&priv->uri, g_free);
	g_clear_pointer (&priv->response, g_free);

	if (priv->config) {
		g_signal_handlers_disconnect_by_func (priv->config, config_changed_cb, self);
		g_clear_object (&priv->config);
	}

	curl_multi_cleanup (priv->curl_mhandle);
	curl_global_cleanup ();
	nm_clear_g_source (&priv->periodic_check_id);

	G_OBJECT_CLASS (nm_connectivity_parent_class)->dispose (object);
}

static void
nm_connectivity_class_init (NMConnectivityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	signals[PERIODIC_CHECK] =
	    g_signal_new (NM_CONNECTIVITY_PERIODIC_CHECK,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	object_class->dispose = dispose;
}
