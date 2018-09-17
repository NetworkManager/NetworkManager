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

#include "c-list/src/c-list.h"
#include "nm-config.h"
#include "NetworkManagerUtils.h"

#define HEADER_STATUS_ONLINE "X-NetworkManager-Status: online\r\n"

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_state_to_string, int /*NMConnectivityState*/,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("???"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_UNKNOWN,  "UNKNOWN"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_NONE,     "NONE"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_LIMITED,  "LIMITED"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_PORTAL,   "PORTAL"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_FULL,     "FULL"),

	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_ERROR,     "ERROR"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_FAKE,      "FAKE"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_CANCELLED, "CANCELLED"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONNECTIVITY_DISPOSING, "DISPOSING"),
);

const char *
nm_connectivity_state_to_string (NMConnectivityState state)
{
	return _state_to_string (state);
}

/*****************************************************************************/

struct _NMConnectivityCheckHandle {
	CList handles_lst;
	NMConnectivity *self;
	NMConnectivityCheckCallback callback;
	gpointer user_data;

	char *ifspec;

#if WITH_CONCHECK
	struct {
		char *response;

		CURL *curl_ehandle;
		struct curl_slist *request_headers;

		GString *recv_msg;
	} concheck;
#endif

	const char *completed_log_message;
	char *completed_log_message_free;
	NMConnectivityState completed_state;

	guint timeout_id;
};

enum {
	CONFIG_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	CList handles_lst_head;
	CList completed_handles_lst_head;
	char *uri;
	char *response;
	gboolean enabled;
	guint interval;
	NMConfig *config;
#if WITH_CONCHECK
	struct {
		CURLM *curl_mhandle;
		guint curl_timer;
	} concheck;
#endif
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
                     (cb_data->ifspec ? &cb_data->ifspec[3] : NULL), \
                     NULL, \
                     "connectivity: (%s) " \
                     _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     (cb_data->ifspec ? &cb_data->ifspec[3] : "") \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static void
cb_data_complete (NMConnectivityCheckHandle *cb_data,
                  NMConnectivityState state,
                  const char *log_message)
{
	NMConnectivity *self;

	nm_assert (cb_data);
	nm_assert (NM_IS_CONNECTIVITY (cb_data->self));
	nm_assert (cb_data->callback);
	nm_assert (state != NM_CONNECTIVITY_UNKNOWN);
	nm_assert (log_message);

	self = cb_data->self;

	/* mark the handle as completing. After this point, nm_connectivity_check_cancel()
	 * is no longer possible. */
	cb_data->self = NULL;

	c_list_unlink_stale (&cb_data->handles_lst);

#if WITH_CONCHECK
	if (cb_data->concheck.curl_ehandle) {
		NMConnectivityPrivate *priv;

		/* Contrary to what cURL manual claim it is *not* safe to remove
		 * the easy handle "at any moment"; specifically it's not safe to
		 * remove *any* handle from within a libcurl callback. That is
		 * why we queue completed handles in this case.
		 *
		 * cb_data_complete() is however only called *not* from within a
		 * libcurl callback. So, this is fine. */
		curl_easy_setopt (cb_data->concheck.curl_ehandle, CURLOPT_WRITEFUNCTION, NULL);
		curl_easy_setopt (cb_data->concheck.curl_ehandle, CURLOPT_WRITEDATA, NULL);
		curl_easy_setopt (cb_data->concheck.curl_ehandle, CURLOPT_HEADERFUNCTION, NULL);
		curl_easy_setopt (cb_data->concheck.curl_ehandle, CURLOPT_HEADERDATA, NULL);
		curl_easy_setopt (cb_data->concheck.curl_ehandle, CURLOPT_PRIVATE, NULL);
		curl_easy_setopt (cb_data->concheck.curl_ehandle, CURLOPT_HTTPHEADER, NULL);

		priv = NM_CONNECTIVITY_GET_PRIVATE (self);

		curl_multi_remove_handle (priv->concheck.curl_mhandle, cb_data->concheck.curl_ehandle);
		curl_easy_cleanup (cb_data->concheck.curl_ehandle);

		curl_slist_free_all (cb_data->concheck.request_headers);
	}
#endif

	nm_clear_g_source (&cb_data->timeout_id);

	_LOG2D ("check completed: %s; %s",
	        nm_connectivity_state_to_string (state),
	        log_message);

	cb_data->callback (self,
	                   cb_data,
	                   state,
	                   cb_data->user_data);

	/* Note: self might be a danling pointer at this point. It must not be used
	 * after this point, and all callers must either take a reference first, or
	 * not use the self pointer too. */

#if WITH_CONCHECK
	g_free (cb_data->concheck.response);
	if (cb_data->concheck.recv_msg)
		g_string_free (cb_data->concheck.recv_msg, TRUE);
#endif
	g_free (cb_data->ifspec);
	if (cb_data->completed_log_message_free)
		g_free (cb_data->completed_log_message_free);
	g_slice_free (NMConnectivityCheckHandle, cb_data);
}

/*****************************************************************************/

#if WITH_CONCHECK

static void
cb_data_queue_completed (NMConnectivityCheckHandle *cb_data,
                         NMConnectivityState state,
                         const char *log_message_static,
                         char *log_message_take /* take */)
{
	nm_assert (cb_data);
	nm_assert (NM_IS_CONNECTIVITY (cb_data->self));
	nm_assert (state != NM_CONNECTIVITY_UNKNOWN);
	nm_assert (log_message_static || log_message_take);
	nm_assert (cb_data->completed_state == NM_CONNECTIVITY_UNKNOWN);
	nm_assert (!cb_data->completed_log_message);
	nm_assert (c_list_contains (&NM_CONNECTIVITY_GET_PRIVATE (cb_data->self)->handles_lst_head, &cb_data->handles_lst));

	cb_data->completed_state = state;
	cb_data->completed_log_message = log_message_static ?: log_message_take;
	cb_data->completed_log_message_free = log_message_take;

	c_list_unlink_stale (&cb_data->handles_lst);
	c_list_link_tail (&NM_CONNECTIVITY_GET_PRIVATE (cb_data->self)->completed_handles_lst_head, &cb_data->handles_lst);
}

static void
_complete_queued (NMConnectivity *self)
{
	NMConnectivity *self_keep_alive = NULL;
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	NMConnectivityCheckHandle *cb_data;

	while ((cb_data = c_list_first_entry (&priv->completed_handles_lst_head, NMConnectivityCheckHandle, handles_lst))) {
		if (!self_keep_alive)
			self_keep_alive = g_object_ref (self);
		cb_data_complete (cb_data,
		                  cb_data->completed_state,
		                  cb_data->completed_log_message);
	}
	nm_g_object_unref (self_keep_alive);
}

static const char *
_check_handle_get_response (NMConnectivityCheckHandle *cb_data)
{
	return cb_data->concheck.response ?: NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE;
}

static gboolean
_con_curl_check_connectivity (CURLM *mhandle, int sockfd, int ev_bitmask)
{
	NMConnectivityCheckHandle *cb_data;
	CURLMsg *msg;
	CURLcode eret;
	int m_left;
	long response_code;
	CURLMcode ret;
	int running_handles;
	gboolean success = TRUE;

	ret = curl_multi_socket_action (mhandle, sockfd, ev_bitmask, &running_handles);
	if (ret != CURLM_OK) {
		_LOGD ("connectivity check failed: %d", ret);
		success = FALSE;
	}

	while ((msg = curl_multi_info_read (mhandle, &m_left))) {

		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Here we have completed a session. Check easy session result. */
		eret = curl_easy_getinfo (msg->easy_handle, CURLINFO_PRIVATE, (char **) &cb_data);
		if (eret != CURLE_OK) {
			_LOGD ("curl cannot extract cb_data for easy handle, skipping msg");
			success = FALSE;
			continue;
		}

		nm_assert (cb_data);
		nm_assert (NM_IS_CONNECTIVITY (cb_data->self));

		if (cb_data->completed_state != NM_CONNECTIVITY_UNKNOWN) {
			/* callback was already invoked earlier. Nothing to do. */
			continue;
		}

		if (msg->data.result != CURLE_OK) {
			cb_data_queue_completed (cb_data,
			                         NM_CONNECTIVITY_LIMITED,
			                         NULL,
			                         g_strdup_printf ("check failed with curl status %d", msg->data.result));
		} else if (   !((_check_handle_get_response (cb_data))[0])
		           && (curl_easy_getinfo (msg->easy_handle, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK)
		           && response_code == 204) {
			/* If we got a 204 response code (no content) and we actually
			 * requested no content, report full connectivity. */
			cb_data_queue_completed (cb_data,
			                         NM_CONNECTIVITY_FULL,
			                         "no content, as expected",
			                         NULL);
		} else {
			/* If we get here, it means that easy_write_cb() didn't read enough
			 * bytes to be able to do a match, or that we were asking for no content
			 * (204 response code) and we actually got some. Either way, that is
			 * an indication of a captive portal */
			cb_data_queue_completed (cb_data,
			                         NM_CONNECTIVITY_PORTAL,
			                         "unexpected short response",
			                         NULL);
		}
	}

	/* if we return a failure, we don't know what went wrong. It's likely serious, because
	 * a failure here is not expected. Return FALSE, so that we stop polling the file descriptor.
	 * Worst case, this leaves the pending connectivity check unhandled, until our regular
	 * time-out kicks in. */
	return success;
}

static gboolean
_con_curl_timeout_cb (gpointer user_data)
{
	gs_unref_object NMConnectivity *self = g_object_ref (NM_CONNECTIVITY (user_data));
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	priv->concheck.curl_timer = 0;
	_con_curl_check_connectivity (priv->concheck.curl_mhandle, CURL_SOCKET_TIMEOUT, 0);
	_complete_queued (self);
	return G_SOURCE_REMOVE;
}

static int
multi_timer_cb (CURLM *multi, long timeout_ms, void *userdata)
{
	NMConnectivity *self = NM_CONNECTIVITY (userdata);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	nm_clear_g_source (&priv->concheck.curl_timer);
	if (timeout_ms != -1)
		priv->concheck.curl_timer = g_timeout_add (timeout_ms, _con_curl_timeout_cb, self);
	return 0;
}

typedef struct {
	NMConnectivity *self;
	GIOChannel *ch;

	/* this is a very simplistic weak-pointer. If ConCurlSockData gets
	 * destroyed, it will set *destroy_notify to TRUE.
	 *
	 * _con_curl_socketevent_cb() uses this to detect whether it can
	 * safely access @fdp after _con_curl_check_connectivity(). */
	gboolean *destroy_notify;

	guint ev;
} ConCurlSockData;

static gboolean
_con_curl_socketevent_cb (GIOChannel *ch, GIOCondition condition, gpointer user_data)
{
	ConCurlSockData *fdp = user_data;
	gs_unref_object NMConnectivity *self = g_object_ref (fdp->self);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	int fd = g_io_channel_unix_get_fd (ch);
	int action = 0;
	gboolean fdp_destroyed = FALSE;
	gboolean success;

	if (condition & G_IO_IN)
		action |= CURL_CSELECT_IN;
	if (condition & G_IO_OUT)
		action |= CURL_CSELECT_OUT;
	if (condition & G_IO_ERR)
		action |= CURL_CSELECT_ERR;

	nm_assert (!fdp->destroy_notify);
	fdp->destroy_notify = &fdp_destroyed;

	success = _con_curl_check_connectivity (priv->concheck.curl_mhandle, fd, action);

	if (fdp_destroyed) {
		/* hups. fdp got invalidated during _con_curl_check_connectivity(). That's fine,
		 * just don't touch it. */
	} else {
		nm_assert (fdp->destroy_notify == &fdp_destroyed);
		fdp->destroy_notify = NULL;
		if (!success)
			fdp->ev = 0;
	}

	_complete_queued (self);

	return success ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

static int
multi_socket_cb (CURL *e_handle, curl_socket_t fd, int what, void *userdata, void *socketp)
{
	NMConnectivity *self = NM_CONNECTIVITY (userdata);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	ConCurlSockData *fdp = socketp;
	GIOCondition condition = 0;

	(void) _NM_ENSURE_TYPE (int, fd);

	if (what == CURL_POLL_REMOVE) {
		if (fdp) {
			if (fdp->destroy_notify)
				*fdp->destroy_notify = TRUE;
			curl_multi_assign (priv->concheck.curl_mhandle, fd, NULL);
			nm_clear_g_source (&fdp->ev);
			g_io_channel_unref (fdp->ch);
			g_slice_free (ConCurlSockData, fdp);
		}
	} else {
		if (!fdp) {
			fdp = g_slice_new0 (ConCurlSockData);
			fdp->self = self;
			fdp->ch = g_io_channel_unix_new (fd);
			curl_multi_assign (priv->concheck.curl_mhandle, fd, fdp);
		} else
			nm_clear_g_source (&fdp->ev);

		if (what == CURL_POLL_IN)
			condition = G_IO_IN;
		else if (what == CURL_POLL_OUT)
			condition = G_IO_OUT;
		else if (what == CURL_POLL_INOUT)
			condition = G_IO_IN | G_IO_OUT;

		if (condition)
			fdp->ev = g_io_add_watch (fdp->ch, condition, _con_curl_socketevent_cb, fdp);
	}

	return CURLM_OK;
}

static size_t
easy_header_cb (char *buffer, size_t size, size_t nitems, void *userdata)
{
	NMConnectivityCheckHandle *cb_data = userdata;
	size_t len = size * nitems;

	if (cb_data->completed_state != NM_CONNECTIVITY_UNKNOWN) {
		/* already completed. */
		return 0;
	}

	if (   len >= sizeof (HEADER_STATUS_ONLINE) - 1
	    && !g_ascii_strncasecmp (buffer, HEADER_STATUS_ONLINE, sizeof (HEADER_STATUS_ONLINE) - 1)) {
		cb_data_queue_completed (cb_data,
		                         NM_CONNECTIVITY_FULL,
		                         "status header found",
		                         NULL);
		return 0;
	}

	return len;
}

static size_t
easy_write_cb (void *buffer, size_t size, size_t nmemb, void *userdata)
{
	NMConnectivityCheckHandle *cb_data = userdata;
	size_t len = size * nmemb;
	const char *response;

	if (cb_data->completed_state != NM_CONNECTIVITY_UNKNOWN) {
		/* already completed. */
		return 0;
	}

	if (!cb_data->concheck.recv_msg)
		cb_data->concheck.recv_msg = g_string_sized_new (len + 10);

	g_string_append_len (cb_data->concheck.recv_msg, buffer, len);

	response = _check_handle_get_response (cb_data);;
	if (   response
	    && cb_data->concheck.recv_msg->len >= strlen (response)) {
		/* We already have enough data -- check response */
		if (g_str_has_prefix (cb_data->concheck.recv_msg->str, response)) {
			cb_data_queue_completed (cb_data,
			                         NM_CONNECTIVITY_FULL,
			                         "expected response",
			                         NULL);
		} else {
			cb_data_queue_completed (cb_data,
			                         NM_CONNECTIVITY_PORTAL,
			                         "unexpected response",
			                         NULL);
		}
		return 0;
	}

	return len;
}

static gboolean
_timeout_cb (gpointer user_data)
{
	NMConnectivityCheckHandle *cb_data = user_data;

	nm_assert (NM_IS_CONNECTIVITY (cb_data->self));
	nm_assert (c_list_contains (&NM_CONNECTIVITY_GET_PRIVATE (cb_data->self)->handles_lst_head, &cb_data->handles_lst));

	cb_data_complete (cb_data, NM_CONNECTIVITY_LIMITED, "timeout");
	return G_SOURCE_REMOVE;
}
#endif

static gboolean
_idle_cb (gpointer user_data)
{
	NMConnectivityCheckHandle *cb_data = user_data;

	nm_assert (NM_IS_CONNECTIVITY (cb_data->self));
	nm_assert (c_list_contains (&NM_CONNECTIVITY_GET_PRIVATE (cb_data->self)->handles_lst_head, &cb_data->handles_lst));

	cb_data->timeout_id = 0;
	if (!cb_data->ifspec) {
		gs_free_error GError *error = NULL;

		/* the invocation was with an invalid ifname. It is a fail. */
		g_set_error (&error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
		             "no interface specified for connectivity check");
		cb_data_complete (cb_data, NM_CONNECTIVITY_ERROR, "missing interface");
	} else
		cb_data_complete (cb_data, NM_CONNECTIVITY_FAKE, "fake result");
	return G_SOURCE_REMOVE;
}

NMConnectivityCheckHandle *
nm_connectivity_check_start (NMConnectivity *self,
                             const char *iface,
                             NMConnectivityCheckCallback callback,
                             gpointer user_data)
{
	NMConnectivityPrivate *priv;
	NMConnectivityCheckHandle *cb_data;

	g_return_val_if_fail (NM_IS_CONNECTIVITY (self), NULL);
	g_return_val_if_fail (!iface || iface[0], NULL);
	g_return_val_if_fail (callback, NULL);

	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	cb_data = g_slice_new0 (NMConnectivityCheckHandle);
	cb_data->self = self;
	c_list_link_tail (&priv->handles_lst_head, &cb_data->handles_lst);
	cb_data->callback = callback;
	cb_data->user_data = user_data;
	cb_data->completed_state = NM_CONNECTIVITY_UNKNOWN;

	if (iface)
		cb_data->ifspec = g_strdup_printf ("if!%s", iface);

#if WITH_CONCHECK
	if (iface) {
		CURL *ehandle;

		if (   priv->enabled
		    && (ehandle = curl_easy_init ())) {

			cb_data->concheck.response = g_strdup (priv->response);
			cb_data->concheck.curl_ehandle = ehandle;
			cb_data->concheck.request_headers = curl_slist_append (NULL, "Connection: close");
			curl_easy_setopt (ehandle, CURLOPT_URL, priv->uri);
			curl_easy_setopt (ehandle, CURLOPT_WRITEFUNCTION, easy_write_cb);
			curl_easy_setopt (ehandle, CURLOPT_WRITEDATA, cb_data);
			curl_easy_setopt (ehandle, CURLOPT_HEADERFUNCTION, easy_header_cb);
			curl_easy_setopt (ehandle, CURLOPT_HEADERDATA, cb_data);
			curl_easy_setopt (ehandle, CURLOPT_PRIVATE, cb_data);
			curl_easy_setopt (ehandle, CURLOPT_HTTPHEADER, cb_data->concheck.request_headers);
			curl_easy_setopt (ehandle, CURLOPT_INTERFACE, cb_data->ifspec);
			curl_multi_add_handle (priv->concheck.curl_mhandle, ehandle);

			cb_data->timeout_id = g_timeout_add_seconds (20, _timeout_cb, cb_data);

			_LOG2D ("start request to '%s'", priv->uri);
			return cb_data;
		}
	}
#endif

	_LOG2D ("start fake request");
	cb_data->timeout_id = g_idle_add (_idle_cb, cb_data);
	return cb_data;
}

void
nm_connectivity_check_cancel (NMConnectivityCheckHandle *cb_data)
{
	g_return_if_fail (cb_data);
	g_return_if_fail (NM_IS_CONNECTIVITY (cb_data->self));

	nm_assert (   c_list_contains (&NM_CONNECTIVITY_GET_PRIVATE (cb_data->self)->handles_lst_head,           &cb_data->handles_lst)
	           || c_list_contains (&NM_CONNECTIVITY_GET_PRIVATE (cb_data->self)->completed_handles_lst_head, &cb_data->handles_lst));

	cb_data_complete (cb_data, NM_CONNECTIVITY_CANCELLED, "cancelled");
}

/*****************************************************************************/

gboolean
nm_connectivity_check_enabled (NMConnectivity *self)
{
	g_return_val_if_fail (NM_IS_CONNECTIVITY (self), FALSE);

	return NM_CONNECTIVITY_GET_PRIVATE (self)->enabled;
}

/*****************************************************************************/

guint
nm_connectivity_get_interval (NMConnectivity *self)
{
	return nm_connectivity_check_enabled (self)
	       ? NM_CONNECTIVITY_GET_PRIVATE (self)->interval
	       : 0;
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
			_LOGE ("scheme of '%s' uri doesn't use a scheme that is allowed for connectivity check.", uri);
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
	interval = MIN (interval, (7 * 24 * 3600));
	if (priv->interval != interval) {
		priv->interval = interval;
		changed = TRUE;
	}

	enabled = FALSE;
#if WITH_CONCHECK
	/* connectivity checking also requires a valid URI, interval and
	 * curl_mhandle */
	if (   priv->uri
	    && priv->interval
	    && priv->concheck.curl_mhandle)
		enabled = nm_config_data_get_connectivity_enabled (config_data);
#endif

	if (priv->enabled != enabled) {
		priv->enabled = enabled;
		changed = TRUE;
	}

	/* Set the response. */
	response = nm_config_data_get_connectivity_response (config_data);
	if (!nm_streq0 (response, priv->response)) {
		/* a response %NULL means, NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE. Any other response
		 * (including "") is accepted. */
		g_free (priv->response);
		priv->response = g_strdup (response);
		changed = TRUE;
	}

	if (changed)
		g_signal_emit (self, signals[CONFIG_CHANGED], 0);
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

/*****************************************************************************/

static void
nm_connectivity_init (NMConnectivity *self)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	c_list_init (&priv->handles_lst_head);
	c_list_init (&priv->completed_handles_lst_head);

	priv->config = g_object_ref (nm_config_get ());
	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  self);

#if WITH_CONCHECK
	if (curl_global_init (CURL_GLOBAL_ALL) == CURLE_OK)
		priv->concheck.curl_mhandle = curl_multi_init ();

	if (!priv->concheck.curl_mhandle)
		 _LOGE ("unable to init cURL, connectivity check will not work");
	else {
		curl_multi_setopt (priv->concheck.curl_mhandle, CURLMOPT_SOCKETFUNCTION, multi_socket_cb);
		curl_multi_setopt (priv->concheck.curl_mhandle, CURLMOPT_SOCKETDATA, self);
		curl_multi_setopt (priv->concheck.curl_mhandle, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
		curl_multi_setopt (priv->concheck.curl_mhandle, CURLMOPT_TIMERDATA, self);
		curl_multi_setopt (priv->concheck.curl_mhandle, CURLOPT_VERBOSE, 1);
	}
#endif

	update_config (self, nm_config_get_data (priv->config));
}

static void
dispose (GObject *object)
{
	NMConnectivity *self = NM_CONNECTIVITY (object);
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	NMConnectivityCheckHandle *cb_data;

	nm_assert (c_list_is_empty (&priv->completed_handles_lst_head));

	while ((cb_data = c_list_first_entry (&priv->handles_lst_head,
	                                      NMConnectivityCheckHandle,
	                                      handles_lst)))
		cb_data_complete (cb_data, NM_CONNECTIVITY_DISPOSING, "shutting down");

	g_clear_pointer (&priv->uri, g_free);
	g_clear_pointer (&priv->response, g_free);

#if WITH_CONCHECK
	nm_clear_g_source (&priv->concheck.curl_timer);

	curl_multi_cleanup (priv->concheck.curl_mhandle);
	curl_global_cleanup ();
#endif

	if (priv->config) {
		g_signal_handlers_disconnect_by_func (priv->config, config_changed_cb, self);
		g_clear_object (&priv->config);
	}

	G_OBJECT_CLASS (nm_connectivity_parent_class)->dispose (object);
}

static void
nm_connectivity_class_init (NMConnectivityClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	signals[CONFIG_CHANGED] =
	    g_signal_new (NM_CONNECTIVITY_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	object_class->dispose = dispose;
}
