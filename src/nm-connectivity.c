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
 * Copyright (C) 2016 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-connectivity.h"

#if WITH_CONCHECK
#include <curl/curl.h>
#endif

#include "c-list/src/c-list.h"
#include "nm-core-internal.h"
#include "nm-config.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-manager.h"
#include "dns/nm-dns-manager.h"

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

typedef struct {
	guint ref_count;
	char *uri;
	char *host;
	char *port;
	char *response;
} ConConfig;

struct _NMConnectivityCheckHandle {
	CList handles_lst;
	NMConnectivity *self;
	NMConnectivityCheckCallback callback;
	gpointer user_data;

	char *ifspec;

	const char *completed_log_message;
	char *completed_log_message_free;

#if WITH_CONCHECK
	struct {
		ConConfig *con_config;

		GCancellable *resolve_cancellable;
		CURLM *curl_mhandle;
		CURL *curl_ehandle;
		struct curl_slist *request_headers;
		struct curl_slist *hosts;

		gsize response_good_cnt;

		guint curl_timer;
		int ch_ifindex;
	} concheck;
#endif

	guint64 request_counter;

	int addr_family;

	guint timeout_id;

	NMConnectivityState completed_state;

	bool fail_reason_no_dbus_connection:1;
};

enum {
	CONFIG_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	CList handles_lst_head;
	CList completed_handles_lst_head;
	NMConfig *config;
	ConConfig *con_config;
	guint interval;

	bool enabled:1;
	bool uri_valid:1;
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
                     "connectivity: (%s,IPv%c,%"G_GUINT64_FORMAT") " \
                     _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                     (cb_data->ifspec ? &cb_data->ifspec[3] : ""), \
                     nm_utils_addr_family_to_char (cb_data->addr_family), \
                     cb_data->request_counter \
                     _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
        } \
    } G_STMT_END

/*****************************************************************************/

static ConConfig *
_con_config_ref (ConConfig *con_config)
{
	if (con_config) {
		nm_assert (con_config->ref_count > 0);
		++con_config->ref_count;
	}
	return con_config;
}

static void
_con_config_unref (ConConfig *con_config)
{
	if (!con_config)
		return;

	nm_assert (con_config->ref_count > 0);

	if (--con_config->ref_count != 0)
		return;

	g_free (con_config->uri);
	g_free (con_config->host);
	g_free (con_config->port);
	g_free (con_config->response);
	g_slice_free (ConConfig, con_config);
}

static const char *
_con_config_get_response (const ConConfig *con_config)
{
	return con_config->response ?: NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE;
}

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

		curl_multi_remove_handle (cb_data->concheck.curl_mhandle,
		                          cb_data->concheck.curl_ehandle);
		curl_easy_cleanup (cb_data->concheck.curl_ehandle);
		curl_multi_cleanup (cb_data->concheck.curl_mhandle);

		curl_slist_free_all (cb_data->concheck.request_headers);
		curl_slist_free_all (cb_data->concheck.hosts);
	}
	nm_clear_g_source (&cb_data->concheck.curl_timer);
	nm_clear_g_cancellable (&cb_data->concheck.resolve_cancellable);
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
	_con_config_unref (cb_data->concheck.con_config);
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
		_LOGD ("connectivity check failed: (%d) %s", ret, curl_easy_strerror (ret));
		success = FALSE;
	}

	while ((msg = curl_multi_info_read (mhandle, &m_left))) {
		const char *response;

		if (msg->msg != CURLMSG_DONE)
			continue;

		/* Here we have completed a session. Check easy session result. */
		eret = curl_easy_getinfo (msg->easy_handle, CURLINFO_PRIVATE, (char **) &cb_data);
		if (eret != CURLE_OK) {
			_LOGD ("curl cannot extract cb_data for easy handle, skipping msg: (%d) %s",
			       eret, curl_easy_strerror (eret));
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
			                         g_strdup_printf ("check failed: (%d) %s",
			                                          msg->data.result,
			                                          curl_easy_strerror (msg->data.result)));
			continue;
		}

		response = _con_config_get_response (cb_data->concheck.con_config);

		if (   response[0] == '\0'
		    && (curl_easy_getinfo (msg->easy_handle, CURLINFO_RESPONSE_CODE, &response_code) == CURLE_OK)) {

			if (response_code == 204) {
				/* We expected an empty response, and we got a 204 response code (no content).
				 * We may or may not have received any content (we would ignore it).
				 * Anyway, the response_code 204 means we are good. */
				cb_data_queue_completed (cb_data,
				                         NM_CONNECTIVITY_FULL,
				                         "no content, as expected",
				                         NULL);
				continue;
			}

			if (   response_code == 200
			    && cb_data->concheck.response_good_cnt == 0) {
				/* we expected no response, and indeed we got an empty reply (with status code 200) */
				cb_data_queue_completed (cb_data,
				                         NM_CONNECTIVITY_FULL,
				                         "empty response, as expected",
				                         NULL);
				continue;
			}
		}

		/* If we get here, it means that easy_write_cb() didn't read enough
		 * bytes to be able to do a match, or that we were asking for no content
		 * (204 response code) and we actually got some. Either way, that is
		 * an indication of a captive portal */
		cb_data_queue_completed (cb_data,
		                         NM_CONNECTIVITY_PORTAL,
		                         "unexpected short response",
		                         NULL);
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
	NMConnectivityCheckHandle *cb_data = user_data;

	cb_data->concheck.curl_timer = 0;
	_con_curl_check_connectivity (cb_data->concheck.curl_mhandle, CURL_SOCKET_TIMEOUT, 0);
	_complete_queued (cb_data->self);
	return G_SOURCE_REMOVE;
}

static int
multi_timer_cb (CURLM *multi, long timeout_ms, void *userdata)
{
	NMConnectivityCheckHandle *cb_data = userdata;

	nm_clear_g_source (&cb_data->concheck.curl_timer);
	if (timeout_ms != -1)
		cb_data->concheck.curl_timer = g_timeout_add (timeout_ms, _con_curl_timeout_cb, cb_data);
	return 0;
}

typedef struct {
	NMConnectivityCheckHandle *cb_data;
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
	NMConnectivityCheckHandle *cb_data = fdp->cb_data;
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

	success = _con_curl_check_connectivity (cb_data->concheck.curl_mhandle, fd, action);

	if (fdp_destroyed) {
		/* hups. fdp got invalidated during _con_curl_check_connectivity(). That's fine,
		 * just don't touch it. */
	} else {
		nm_assert (fdp->destroy_notify == &fdp_destroyed);
		fdp->destroy_notify = NULL;
		if (!success)
			fdp->ev = 0;
	}

	_complete_queued (cb_data->self);

	return success ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

static int
multi_socket_cb (CURL *e_handle, curl_socket_t fd, int what, void *userdata, void *socketp)
{
	NMConnectivityCheckHandle *cb_data = userdata;
	ConCurlSockData *fdp = socketp;
	GIOCondition condition = 0;

	(void) _NM_ENSURE_TYPE (int, fd);

	if (what == CURL_POLL_REMOVE) {
		if (fdp) {
			if (fdp->destroy_notify)
				*fdp->destroy_notify = TRUE;
			curl_multi_assign (cb_data->concheck.curl_mhandle, fd, NULL);
			nm_clear_g_source (&fdp->ev);
			g_io_channel_unref (fdp->ch);
			g_slice_free (ConCurlSockData, fdp);
		}
	} else {
		if (!fdp) {
			fdp = g_slice_new0 (ConCurlSockData);
			fdp->cb_data = cb_data;
			fdp->ch = g_io_channel_unix_new (fd);
			curl_multi_assign (cb_data->concheck.curl_mhandle, fd, fdp);
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
	size_t response_len;
	size_t check_len;
	const char *response;

	if (cb_data->completed_state != NM_CONNECTIVITY_UNKNOWN) {
		/* already completed. */
		return 0;
	}

	if (len == 0) {
		/* no data. That can happen, it's fine. */
		return len;
	}

	response = _con_config_get_response (cb_data->concheck.con_config);;

	if (response[0] == '\0') {
		/* no response expected. We are however graceful and accept any
		 * extra response that we might receive. We determine the empty
		 * response based on the status code 204.
		 *
		 * Continue receiving... */
		cb_data->concheck.response_good_cnt += len;

		if (cb_data->concheck.response_good_cnt > (gsize) (100 * 1024)) {
			/* we expect an empty response. We accept either
			 * 1) status code 204 and any response
			 * 2) status code 200 and an empty response.
			 *
			 * Here, we want to continue receiving data, to see whether we have
			 * case 1). Arguably, the server shouldn't send us 204 with a non-empty
			 * response, but we accept that also with a non-empty response, so
			 * keep receiving.
			 *
			 * However, if we get an excessive amount of data, we put a stop on it
			 * and fail. */
			cb_data_queue_completed (cb_data,
			                         NM_CONNECTIVITY_PORTAL,
			                         "unexpected non-empty response",
			                         NULL);
			return 0;
		}

		return len;
	}

	nm_assert (cb_data->concheck.response_good_cnt < strlen (response));

	response_len = strlen (response);

	check_len = NM_MIN (len,
	                    response_len - cb_data->concheck.response_good_cnt);

	if (strncmp (&response[cb_data->concheck.response_good_cnt],
	             buffer,
	             check_len) != 0) {
		cb_data_queue_completed (cb_data,
		                         NM_CONNECTIVITY_PORTAL,
		                         "unexpected response",
		                         NULL);
		return 0;
	}

	cb_data->concheck.response_good_cnt += len;

	if (cb_data->concheck.response_good_cnt >= response_len) {
		/* We already have enough data, and it matched. */
		cb_data_queue_completed (cb_data,
		                         NM_CONNECTIVITY_FULL,
		                         "expected response",
		                         NULL);
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
	} else if (cb_data->fail_reason_no_dbus_connection) {
		gs_free_error GError *error = NULL;

		g_set_error (&error, NM_UTILS_ERROR, NM_UTILS_ERROR_INVALID_ARGUMENT,
		             "no D-Bus connection");
		cb_data_complete (cb_data, NM_CONNECTIVITY_ERROR, "no D-Bus connection");
	} else
		cb_data_complete (cb_data, NM_CONNECTIVITY_FAKE, "fake result");
	return G_SOURCE_REMOVE;
}

static void
do_curl_request (NMConnectivityCheckHandle *cb_data)
{
	CURLM *mhandle;
	CURL *ehandle;
	long resolve;

	mhandle = curl_multi_init ();
	if (!mhandle) {
		cb_data_complete (cb_data, NM_CONNECTIVITY_ERROR, "curl error");
		return;
	}

	ehandle = curl_easy_init ();
	if (!ehandle) {
		curl_multi_cleanup (mhandle);
		cb_data_complete (cb_data, NM_CONNECTIVITY_ERROR, "curl error");
		return;
	}

	cb_data->concheck.curl_mhandle = mhandle;
	cb_data->concheck.curl_ehandle = ehandle;
	cb_data->concheck.request_headers = curl_slist_append (NULL, "Connection: close");
	cb_data->timeout_id = g_timeout_add_seconds (20, _timeout_cb, cb_data);

	curl_multi_setopt (mhandle, CURLMOPT_SOCKETFUNCTION, multi_socket_cb);
	curl_multi_setopt (mhandle, CURLMOPT_SOCKETDATA, cb_data);
	curl_multi_setopt (mhandle, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
	curl_multi_setopt (mhandle, CURLMOPT_TIMERDATA, cb_data);
	curl_multi_setopt (mhandle, CURLOPT_VERBOSE, 1);

	switch (cb_data->addr_family) {
	case AF_INET:
		resolve = CURL_IPRESOLVE_V4;
		break;
	case AF_INET6:
		resolve = CURL_IPRESOLVE_V6;
		break;
	case AF_UNSPEC:
		resolve = CURL_IPRESOLVE_WHATEVER;
		break;
	default:
		resolve = CURL_IPRESOLVE_WHATEVER;
		g_warn_if_reached ();
	}

	curl_easy_setopt (ehandle, CURLOPT_URL, cb_data->concheck.con_config->uri);
	curl_easy_setopt (ehandle, CURLOPT_WRITEFUNCTION, easy_write_cb);
	curl_easy_setopt (ehandle, CURLOPT_WRITEDATA, cb_data);
	curl_easy_setopt (ehandle, CURLOPT_HEADERFUNCTION, easy_header_cb);
	curl_easy_setopt (ehandle, CURLOPT_HEADERDATA, cb_data);
	curl_easy_setopt (ehandle, CURLOPT_PRIVATE, cb_data);
	curl_easy_setopt (ehandle, CURLOPT_HTTPHEADER, cb_data->concheck.request_headers);
	curl_easy_setopt (ehandle, CURLOPT_INTERFACE, cb_data->ifspec);
	curl_easy_setopt (ehandle, CURLOPT_RESOLVE, cb_data->concheck.hosts);
	curl_easy_setopt (ehandle, CURLOPT_IPRESOLVE, resolve);

	curl_multi_add_handle (mhandle, ehandle);
}

static void
resolve_cb (GObject *object, GAsyncResult *res, gpointer user_data)
{
	NMConnectivityCheckHandle *cb_data;
	gs_unref_variant GVariant *result = NULL;
	gs_unref_variant GVariant *addresses = NULL;
	gsize no_addresses;
	int ifindex;
	int addr_family;
	gsize len = 0;
	gsize i;
	gs_free_error GError *error = NULL;

	result = g_dbus_connection_call_finish (G_DBUS_CONNECTION (object), res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	cb_data = user_data;

	g_clear_object (&cb_data->concheck.resolve_cancellable);

	if (!result) {
		/* Never mind. Just let do curl do its own resolving. */
		_LOG2D ("can't resolve a name via systemd-resolved: %s", error->message);
		do_curl_request (cb_data);
		return;
	}

	addresses = g_variant_get_child_value (result, 0);
	no_addresses = g_variant_n_children (addresses);

	for (i = 0; i < no_addresses; i++) {
		gs_unref_variant GVariant *address = NULL;
		char str_addr[NM_UTILS_INET_ADDRSTRLEN];
		gs_free char *host_entry = NULL;
		const guchar *address_buf;

		g_variant_get_child (addresses, i, "(ii@ay)", &ifindex, &addr_family, &address);

		if (   cb_data->addr_family != AF_UNSPEC
		    && cb_data->addr_family != addr_family)
			continue;

		address_buf = g_variant_get_fixed_array (address, &len, 1);
		if (   (addr_family == AF_INET  && len != sizeof (struct in_addr))
		    || (addr_family == AF_INET6 && len != sizeof (struct in6_addr)))
			continue;

		host_entry = g_strdup_printf ("%s:%s:%s",
		                              cb_data->concheck.con_config->host,
		                              cb_data->concheck.con_config->port ?: "80",
		                              nm_utils_inet_ntop (addr_family, address_buf, str_addr));
		cb_data->concheck.hosts = curl_slist_append (cb_data->concheck.hosts, host_entry);
		_LOG2T ("adding '%s' to curl resolve list", host_entry);
	}

	do_curl_request (cb_data);
}

#define SD_RESOLVED_DNS ((guint64) (1LL << 0))

NMConnectivityCheckHandle *
nm_connectivity_check_start (NMConnectivity *self,
                             int addr_family,
                             int ifindex,
                             const char *iface,
                             NMConnectivityCheckCallback callback,
                             gpointer user_data)
{
	NMConnectivityPrivate *priv;
	NMConnectivityCheckHandle *cb_data;
	static guint64 request_counter = 0;

	g_return_val_if_fail (NM_IS_CONNECTIVITY (self), NULL);
	g_return_val_if_fail (callback, NULL);

	priv = NM_CONNECTIVITY_GET_PRIVATE (self);

	cb_data = g_slice_new0 (NMConnectivityCheckHandle);
	cb_data->self = self;
	cb_data->request_counter = ++request_counter;
	c_list_link_tail (&priv->handles_lst_head, &cb_data->handles_lst);
	cb_data->callback = callback;
	cb_data->user_data = user_data;
	cb_data->completed_state = NM_CONNECTIVITY_UNKNOWN;
	cb_data->addr_family = addr_family;
	cb_data->concheck.con_config = _con_config_ref (priv->con_config);

	if (iface)
		cb_data->ifspec = g_strdup_printf ("if!%s", iface);

#if WITH_CONCHECK

	if (   iface
	    && ifindex > 0
	    && priv->enabled
	    && priv->uri_valid) {
		gboolean has_systemd_resolved;

		cb_data->concheck.ch_ifindex = ifindex;

		/* note that we pick up support for systemd-resolved right away when we need it.
		 * We don't need to remember the setting, because we can (cheaply) check anew
		 * on each request.
		 *
		 * Yes, this makes NMConnectivity singleton dependent on NMDnsManager singleton.
		 * Well, not really: it makes connectivity-check-start dependent on NMDnsManager
		 * which merely means, not to start a connectivity check, late during shutdown. */
		has_systemd_resolved = nm_dns_manager_has_systemd_resolved (nm_dns_manager_get ());

		if (has_systemd_resolved) {
			GDBusConnection *dbus_connection;

			dbus_connection = nm_dbus_manager_get_dbus_connection (nm_dbus_manager_get ());
			if (!dbus_connection) {
				/* we have no D-Bus connection? That might happen in configure and quit mode.
				 *
				 * Anyway, something is very odd, just fail connectivity check. */
				_LOG2D ("start fake request (fail due to no D-Bus connection)");
				cb_data->fail_reason_no_dbus_connection = TRUE;
				cb_data->timeout_id = g_idle_add (_idle_cb, cb_data);
				return cb_data;
			}

			cb_data->concheck.resolve_cancellable = g_cancellable_new ();

			g_dbus_connection_call (nm_dbus_manager_get_dbus_connection (nm_dbus_manager_get ()),
			                        "org.freedesktop.resolve1",
			                        "/org/freedesktop/resolve1",
			                        "org.freedesktop.resolve1.Manager",
			                        "ResolveHostname",
			                        g_variant_new ("(isit)",
			                                       (gint32) cb_data->concheck.ch_ifindex,
			                                       cb_data->concheck.con_config->host,
			                                       (gint32) cb_data->addr_family,
			                                       SD_RESOLVED_DNS),
			                        G_VARIANT_TYPE ("(a(iiay)st)"),
			                        G_DBUS_CALL_FLAGS_NONE,
			                        -1,
			                        cb_data->concheck.resolve_cancellable,
			                        resolve_cb,
			                        cb_data);
			_LOG2D ("start request to '%s' (try resolving '%s' using systemd-resolved)",
			        cb_data->concheck.con_config->uri,
			        cb_data->concheck.con_config->host);
		} else {
			_LOG2D ("start request to '%s' (systemd-resolved not available)",
			        cb_data->concheck.con_config->uri);
			do_curl_request (cb_data);
		}

		return cb_data;
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

static gboolean
host_and_port_from_uri (const char *uri, char **host, char **port)
{
	const char *p = uri;
	const char *host_begin = NULL;
	size_t host_len = 0;
	const char *port_begin = NULL;
	size_t port_len = 0;

	/* scheme */
	while (*p != ':' && *p != '/') {
		if (!*p++)
			return FALSE;
	}

	/* :// */
	if (*p++ != ':')
		return FALSE;
	if (*p++ != '/')
		return FALSE;
	if (*p++ != '/')
		return FALSE;
	/* host */
	if (*p == '[')
		return FALSE;
	host_begin = p;
	while (*p && *p != ':' && *p != '/') {
		host_len++;
		p++;
	}
	if (host_len == 0)
		return FALSE;
	*host = g_strndup (host_begin, host_len);

	/* port */
	if (*p++ == ':') {
		port_begin = p;
		while (*p && *p != '/') {
			port_len++;
			p++;
		}
		if (port_len)
			*port = g_strndup (port_begin, port_len);
	}

	return TRUE;
}

static void
update_config (NMConnectivity *self, NMConfigData *config_data)
{
	NMConnectivityPrivate *priv = NM_CONNECTIVITY_GET_PRIVATE (self);
	guint interval;
	gboolean enabled;
	gboolean changed = FALSE;
	const char *cur_uri = priv->con_config ? priv->con_config->uri : NULL;
	const char *cur_response = priv->con_config ? priv->con_config->response : NULL;
	const char *new_response;
	const char *new_uri;
	gboolean new_uri_valid = priv->uri_valid;
	gboolean new_host_port = FALSE;
	gs_free char *new_host = NULL;
	gs_free char *new_port = NULL;

	new_uri = nm_config_data_get_connectivity_uri (config_data);
	if (!nm_streq0 (new_uri, cur_uri)) {

		new_uri_valid = (new_uri && *new_uri);
		if (new_uri_valid) {
			gs_free char *scheme = g_uri_parse_scheme (new_uri);
			gboolean is_https = FALSE;

			if (!scheme) {
				_LOGE ("invalid URI '%s' for connectivity check.", new_uri);
				new_uri_valid = FALSE;
			} else if (g_ascii_strcasecmp (scheme, "https") == 0) {
				_LOGW ("use of HTTPS for connectivity checking is not reliable and is discouraged (URI: %s)", new_uri);
				is_https = TRUE;
			} else if (g_ascii_strcasecmp (scheme, "http") != 0) {
				_LOGE ("scheme of '%s' uri doesn't use a scheme that is allowed for connectivity check.", new_uri);
				new_uri_valid = FALSE;
			}
			if (new_uri_valid) {
				new_host_port = TRUE;
				if (!host_and_port_from_uri (new_uri, &new_host, &new_port)) {
					_LOGE ("cannot parse host and port from '%s'", new_uri);
					new_uri_valid = FALSE;
				} else if (!new_port && is_https)
					new_port = g_strdup ("443");
			}
		}

		if (   new_uri_valid
		    || priv->uri_valid != new_uri_valid)
			changed = TRUE;
	}

	new_response = nm_config_data_get_connectivity_response (config_data);
	if (!nm_streq0 (new_response, cur_response))
		changed = TRUE;

	if (   !priv->con_config
	    || !nm_streq0 (new_uri, priv->con_config->uri)
	    || !nm_streq0 (new_response, priv->con_config->response)) {
		if (!new_host_port) {
			new_host = priv->con_config ? g_strdup (priv->con_config->host) : NULL;
			new_port = priv->con_config ? g_strdup (priv->con_config->port) : NULL;
		}
		_con_config_unref (priv->con_config);
		priv->con_config = g_slice_new (ConConfig);
		*priv->con_config = (ConConfig) {
			.ref_count = 1,
			.uri       = g_strdup (new_uri),
			.response  = g_strdup (new_response),
			.host      = g_steal_pointer (&new_host),
			.port      = g_steal_pointer (&new_port),
		};
	}
	priv->uri_valid = new_uri_valid;

	interval = nm_config_data_get_connectivity_interval (config_data);
	interval = MIN (interval, (7 * 24 * 3600));
	if (priv->interval != interval) {
		priv->interval = interval;
		changed = TRUE;
	}

	enabled = FALSE;
#if WITH_CONCHECK
	if (   priv->uri_valid
	    && priv->interval)
		enabled = nm_config_data_get_connectivity_enabled (config_data);
#endif

	if (priv->enabled != enabled) {
		priv->enabled = enabled;
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
#if WITH_CONCHECK
	CURLcode ret;
#endif

	c_list_init (&priv->handles_lst_head);
	c_list_init (&priv->completed_handles_lst_head);

	priv->config = g_object_ref (nm_config_get ());
	g_signal_connect (G_OBJECT (priv->config),
	                  NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_CALLBACK (config_changed_cb),
	                  self);

#if WITH_CONCHECK
	ret = curl_global_init (CURL_GLOBAL_ALL);
	if (ret != CURLE_OK) {
		_LOGE ("unable to init cURL, connectivity check will not work: (%d) %s",
		       ret, curl_easy_strerror (ret));
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

	nm_clear_pointer (&priv->con_config, _con_config_unref);

#if WITH_CONCHECK
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
