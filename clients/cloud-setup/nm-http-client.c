/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm/nm-default-client.h"

#include "nm-http-client.h"

#include <curl/curl.h>

#include "nm-cloud-setup-utils.h"
#include "nm-glib-aux/nm-str-buf.h"

#define NM_CURL_DEBUG 0

/*****************************************************************************/

typedef struct {
    GMainContext *context;
    CURLM *       mhandle;
    GSource *     mhandle_source_timeout;
    GHashTable *  source_sockets_hashtable;
} NMHttpClientPrivate;

struct _NMHttpClient {
    GObject             parent;
    NMHttpClientPrivate _priv;
};

struct _NMHttpClientClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMHttpClient, nm_http_client, G_TYPE_OBJECT);

#define NM_HTTP_CLIENT_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMHttpClient, NM_IS_HTTP_CLIENT)

/*****************************************************************************/

#define _NMLOG2(level, edata, ...)                               \
    G_STMT_START                                                 \
    {                                                            \
        EHandleData *_edata = (edata);                           \
                                                                 \
        _NMLOG(level,                                            \
               "http-request[" NM_HASH_OBFUSCATE_PTR_FMT         \
               ", \"%s\"]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
               NM_HASH_OBFUSCATE_PTR(_edata),                    \
               (_edata)->url _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    }                                                            \
    G_STMT_END

/*****************************************************************************/

G_LOCK_DEFINE_STATIC(_my_curl_initalized_lock);
static bool _my_curl_initialized = FALSE;

__attribute__((destructor)) static void
_my_curl_global_cleanup(void)
{
    G_LOCK(_my_curl_initalized_lock);
    if (_my_curl_initialized) {
        _my_curl_initialized = FALSE;
        curl_global_cleanup();
    }
    G_UNLOCK(_my_curl_initalized_lock);
}

static void
nm_http_client_curl_global_init(void)
{
    G_LOCK(_my_curl_initalized_lock);
    if (!_my_curl_initialized) {
        _my_curl_initialized = TRUE;
        if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
            /* Even if this fails, we are partly initialized. WTF. */
            _LOGE("curl: curl_global_init() failed!");
        }
    }
    G_UNLOCK(_my_curl_initalized_lock);
}

/*****************************************************************************/

GMainContext *
nm_http_client_get_main_context(NMHttpClient *self)
{
    g_return_val_if_fail(NM_IS_HTTP_CLIENT(self), NULL);

    return NM_HTTP_CLIENT_GET_PRIVATE(self)->context;
}

/*****************************************************************************/

static GSource *
_source_attach(NMHttpClient *self, GSource *source)
{
    return nm_g_source_attach(source, NM_HTTP_CLIENT_GET_PRIVATE(self)->context);
}

/*****************************************************************************/

typedef struct {
    long    response_code;
    GBytes *response_data;
} GetResult;

static void
_get_result_free(gpointer data)
{
    GetResult *get_result = data;

    g_bytes_unref(get_result->response_data);
    nm_g_slice_free(get_result);
}

typedef struct {
    GTask *            task;
    GSource *          timeout_source;
    CURLcode           ehandle_result;
    CURL *             ehandle;
    char *             url;
    NMStrBuf           recv_data;
    struct curl_slist *headers;
    gssize             max_data;
    gulong             cancellable_id;
} EHandleData;

static void
_ehandle_free_ehandle(EHandleData *edata)
{
    if (edata->ehandle) {
        NMHttpClient *       self = g_task_get_source_object(edata->task);
        NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

        curl_multi_remove_handle(priv->mhandle, edata->ehandle);
        curl_easy_cleanup(g_steal_pointer(&edata->ehandle));
    }
}

static void
_ehandle_free(EHandleData *edata)
{
    nm_assert(!edata->ehandle);
    nm_assert(!edata->timeout_source);

    g_object_unref(edata->task);

    nm_str_buf_destroy(&edata->recv_data);
    if (edata->headers)
        curl_slist_free_all(edata->headers);
    g_free(edata->url);
    nm_g_slice_free(edata);
}

static void
_ehandle_complete(EHandleData *edata, GError *error_take)
{
    GetResult *   get_result;
    gs_free char *str_tmp_1     = NULL;
    long          response_code = -1;

    nm_clear_pointer(&edata->timeout_source, nm_g_source_destroy_and_unref);

    nm_clear_g_cancellable_disconnect(g_task_get_cancellable(edata->task), &edata->cancellable_id);

    if (error_take) {
        if (nm_utils_error_is_cancelled(error_take))
            _LOG2T(edata, "cancelled");
        else
            _LOG2D(edata, "failed with %s", error_take->message);
    } else if (edata->ehandle_result != CURLE_OK) {
        _LOG2D(edata, "failed with curl error \"%s\"", curl_easy_strerror(edata->ehandle_result));
        nm_utils_error_set(&error_take,
                           NM_UTILS_ERROR_UNKNOWN,
                           "failed with curl error \"%s\"",
                           curl_easy_strerror(edata->ehandle_result));
    }

    if (error_take) {
        _ehandle_free_ehandle(edata);
        g_task_return_error(edata->task, error_take);
        _ehandle_free(edata);
        return;
    }

    if (curl_easy_getinfo(edata->ehandle, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK)
        _LOG2E(edata, "failed to get response code from curl easy handle");

    _LOG2D(edata,
           "success getting %" G_GSIZE_FORMAT " bytes (response code %ld)",
           edata->recv_data.len,
           response_code);

    _LOG2T(edata,
           "received %" G_GSIZE_FORMAT " bytes: [[%s]]",
           edata->recv_data.len,
           nm_utils_buf_utf8safe_escape(nm_str_buf_get_str(&edata->recv_data),
                                        edata->recv_data.len,
                                        NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                        &str_tmp_1));

    _ehandle_free_ehandle(edata);

    get_result  = g_slice_new(GetResult);
    *get_result = (GetResult){
        .response_code = response_code,
        /* This ensures that response_data is always NUL terminated. This is an important guarantee
         * that NMHttpClient makes. */
        .response_data = nm_str_buf_finalize_to_gbytes(&edata->recv_data),
    };

    g_task_return_pointer(edata->task, get_result, _get_result_free);

    _ehandle_free(edata);
}

/*****************************************************************************/

static size_t
_get_writefunction_cb(char *ptr, size_t size, size_t nmemb, void *user_data)
{
    EHandleData *edata = user_data;
    gsize        nconsume;

    /* size should always be 1, but still. Multiply them to be sure. */
    nmemb *= size;

    if (edata->max_data >= 0) {
        nm_assert(edata->recv_data.len <= edata->max_data);
        nconsume = (((gsize) edata->max_data) - edata->recv_data.len);
        if (nconsume > nmemb)
            nconsume = nmemb;
    } else
        nconsume = nmemb;

    nm_str_buf_append_len(&edata->recv_data, ptr, nconsume);
    return nconsume;
}

static gboolean
_get_timeout_cb(gpointer user_data)
{
    _ehandle_complete(
        user_data,
        g_error_new_literal(NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN, "HTTP request timed out"));
    return G_SOURCE_REMOVE;
}

static void
_get_cancelled_cb(GObject *object, gpointer user_data)
{
    EHandleData *edata = user_data;
    GError *     error = NULL;

    nm_clear_g_signal_handler(g_task_get_cancellable(edata->task), &edata->cancellable_id);
    nm_utils_error_set_cancelled(&error, FALSE, NULL);
    _ehandle_complete(edata, error);
}

void
nm_http_client_get(NMHttpClient *      self,
                   const char *        url,
                   int                 timeout_msec,
                   gssize              max_data,
                   const char *const * http_headers,
                   GCancellable *      cancellable,
                   GAsyncReadyCallback callback,
                   gpointer            user_data)
{
    NMHttpClientPrivate *priv;
    EHandleData *        edata;
    guint                i;

    g_return_if_fail(NM_IS_HTTP_CLIENT(self));
    g_return_if_fail(url);
    g_return_if_fail(!cancellable || G_IS_CANCELLABLE(cancellable));
    g_return_if_fail(timeout_msec >= 0);
    g_return_if_fail(max_data >= -1);

    priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

    edata  = g_slice_new(EHandleData);
    *edata = (EHandleData){
        .task      = nm_g_task_new(self, cancellable, nm_http_client_get, callback, user_data),
        .recv_data = NM_STR_BUF_INIT(0, FALSE),
        .max_data  = max_data,
        .url       = g_strdup(url),
        .headers   = NULL,
    };

    nmcs_wait_for_objects_register(edata->task);

    _LOG2D(edata, "start get ...");

    edata->ehandle = curl_easy_init();
    if (!edata->ehandle) {
        _ehandle_complete(edata,
                          g_error_new_literal(NM_UTILS_ERROR,
                                              NM_UTILS_ERROR_UNKNOWN,
                                              "HTTP request failed to create curl handle"));
        return;
    }

    curl_easy_setopt(edata->ehandle, CURLOPT_URL, url);

    curl_easy_setopt(edata->ehandle, CURLOPT_WRITEFUNCTION, _get_writefunction_cb);
    curl_easy_setopt(edata->ehandle, CURLOPT_WRITEDATA, edata);
    curl_easy_setopt(edata->ehandle, CURLOPT_PRIVATE, edata);

    if (http_headers) {
        for (i = 0; http_headers[i]; ++i) {
            struct curl_slist *tmp;

            tmp = curl_slist_append(edata->headers, http_headers[i]);
            if (!tmp) {
                curl_slist_free_all(tmp);
                _LOGE("curl: curl_slist_append() failed adding %s", http_headers[i]);
                continue;
            }
            edata->headers = tmp;
        }

        curl_easy_setopt(edata->ehandle, CURLOPT_HTTPHEADER, edata->headers);
    }

    if (timeout_msec > 0) {
        edata->timeout_source = _source_attach(self,
                                               nm_g_timeout_source_new(timeout_msec,
                                                                       G_PRIORITY_DEFAULT,
                                                                       _get_timeout_cb,
                                                                       edata,
                                                                       NULL));
    }

    curl_multi_add_handle(priv->mhandle, edata->ehandle);

    if (cancellable) {
        gulong signal_id;

        signal_id = g_cancellable_connect(cancellable, G_CALLBACK(_get_cancelled_cb), edata, NULL);
        if (signal_id == 0) {
            /* the request is already cancelled. Return. */
            return;
        }
        edata->cancellable_id = signal_id;
    }
}

/**
 * nm_http_client_get_finish:
 * @self: the #NMHttpClient instance
 * @result: the #GAsyncResult which to complete.
 * @out_response_code: (allow-none) (out): the HTTP response code or -1 on other error.
 * @out_response_data: (allow-none) (transfer full): the HTTP response data, if any.
 *   The GBytes buffer is guaranteed to have a trailing NUL character *after* the
 *   returned buffer size. That means, you can always trust that the buffer is NUL terminated
 *   and that there is one additional hidden byte after the data.
 *   Also, the returned buffer is allocated just for you. While GBytes is immutable, you are
 *   allowed to modify the buffer as it's not used by anybody else.
 * @error: the error
 *
 * Returns: %TRUE on success or %FALSE with an error code.
 */
gboolean
nm_http_client_get_finish(NMHttpClient *self,
                          GAsyncResult *result,
                          long *        out_response_code,
                          GBytes **     out_response_data,
                          GError **     error)
{
    GetResult *get_result;

    g_return_val_if_fail(NM_IS_HTTP_CLIENT(self), FALSE);
    g_return_val_if_fail(nm_g_task_is_valid(result, self, nm_http_client_get), FALSE);

    get_result = g_task_propagate_pointer(G_TASK(result), error);

    nm_assert(!error || (!!get_result) == (!*error));

    if (!get_result) {
        NM_SET_OUT(out_response_code, -1);
        NM_SET_OUT(out_response_data, NULL);
        return FALSE;
    }

    NM_SET_OUT(out_response_code, get_result->response_code);

    /* response_data is binary, but is also guaranteed to be NUL terminated! */
    NM_SET_OUT(out_response_data, g_steal_pointer(&get_result->response_data));

    _get_result_free(get_result);
    return TRUE;
}

/*****************************************************************************/

typedef struct {
    GTask *                     task;
    char *                      uri;
    const char *const *         http_headers;
    NMHttpClientPollGetCheckFcn check_fcn;
    gpointer                    check_user_data;
    GBytes *                    response_data;
    gsize                       request_max_data;
    long                        response_code;
    int                         request_timeout_ms;
} PollGetData;

static void
_poll_get_data_free(gpointer data)
{
    PollGetData *poll_get_data = data;

    g_free(poll_get_data->uri);

    nm_clear_pointer(&poll_get_data->response_data, g_bytes_unref);
    g_strfreev((char **) poll_get_data->http_headers);

    nm_g_slice_free(poll_get_data);
}

static void
_poll_get_probe_start_fcn(GCancellable *      cancellable,
                          gpointer            probe_user_data,
                          GAsyncReadyCallback callback,
                          gpointer            user_data)
{
    PollGetData *poll_get_data = probe_user_data;

    /* balanced by _poll_get_probe_finish_fcn() */
    g_object_ref(poll_get_data->task);

    nm_http_client_get(g_task_get_source_object(poll_get_data->task),
                       poll_get_data->uri,
                       poll_get_data->request_timeout_ms,
                       poll_get_data->request_max_data,
                       poll_get_data->http_headers,
                       cancellable,
                       callback,
                       user_data);
}

static gboolean
_poll_get_probe_finish_fcn(GObject *     source,
                           GAsyncResult *result,
                           gpointer      probe_user_data,
                           GError **     error)
{
    PollGetData *              poll_get_data = probe_user_data;
    _nm_unused gs_unref_object GTask *task =
        poll_get_data->task; /* balance ref from _poll_get_probe_start_fcn() */
    gboolean      success;
    gs_free_error GError *local_error    = NULL;
    gs_unref_bytes GBytes *response_data = NULL;
    long                   response_code = -1;

    success = nm_http_client_get_finish(g_task_get_source_object(poll_get_data->task),
                                        result,
                                        &response_code,
                                        &response_data,
                                        &local_error);

    nm_assert((!!success) == (!local_error));

    if (local_error) {
        if (nm_utils_error_is_cancelled(local_error)) {
            g_propagate_error(error, g_steal_pointer(&local_error));
            return TRUE;
        }
        /* any other error. Continue polling. */
        return FALSE;
    }

    if (poll_get_data->check_fcn) {
        success = poll_get_data->check_fcn(response_code,
                                           response_data,
                                           poll_get_data->check_user_data,
                                           &local_error);
    } else
        success = (response_code == 200);

    if (local_error) {
        g_propagate_error(error, g_steal_pointer(&local_error));
        return TRUE;
    }

    if (!success) {
        /* Not yet ready. Continue polling. */
        return FALSE;
    }

    poll_get_data->response_code = response_code;
    poll_get_data->response_data = g_steal_pointer(&response_data);
    return TRUE;
}

static void
_poll_get_done_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    PollGetData * poll_get_data = user_data;
    gs_free_error GError *error = NULL;
    gboolean              success;

    success = nmcs_utils_poll_finish(result, NULL, &error);

    nm_assert((!!success) == (!error));

    if (error)
        g_task_return_error(poll_get_data->task, g_steal_pointer(&error));
    else
        g_task_return_boolean(poll_get_data->task, TRUE);

    g_object_unref(poll_get_data->task);
}

void
nm_http_client_poll_get(NMHttpClient *              self,
                        const char *                uri,
                        int                         request_timeout_ms,
                        gssize                      request_max_data,
                        int                         poll_timeout_ms,
                        int                         ratelimit_timeout_ms,
                        const char *const *         http_headers,
                        GCancellable *              cancellable,
                        NMHttpClientPollGetCheckFcn check_fcn,
                        gpointer                    check_user_data,
                        GAsyncReadyCallback         callback,
                        gpointer                    user_data)
{
    nm_auto_pop_gmaincontext GMainContext *context = NULL;
    PollGetData *                          poll_get_data;

    g_return_if_fail(NM_IS_HTTP_CLIENT(self));
    g_return_if_fail(uri && uri[0]);
    g_return_if_fail(request_timeout_ms >= -1);
    g_return_if_fail(request_max_data >= -1);
    g_return_if_fail(poll_timeout_ms >= -1);
    g_return_if_fail(ratelimit_timeout_ms >= -1);
    g_return_if_fail(!cancellable || G_CANCELLABLE(cancellable));

    poll_get_data  = g_slice_new(PollGetData);
    *poll_get_data = (PollGetData){
        .task = nm_g_task_new(self, cancellable, nm_http_client_poll_get, callback, user_data),
        .uri  = g_strdup(uri),
        .request_timeout_ms = request_timeout_ms,
        .request_max_data   = request_max_data,
        .check_fcn          = check_fcn,
        .check_user_data    = check_user_data,
        .response_code      = -1,
        .http_headers       = NM_CAST_STRV_CC(g_strdupv((char **) http_headers)),
    };

    nmcs_wait_for_objects_register(poll_get_data->task);

    g_task_set_task_data(poll_get_data->task, poll_get_data, _poll_get_data_free);

    context =
        nm_g_main_context_push_thread_default_if_necessary(nm_http_client_get_main_context(self));

    nmcs_utils_poll(poll_timeout_ms,
                    ratelimit_timeout_ms,
                    0,
                    _poll_get_probe_start_fcn,
                    _poll_get_probe_finish_fcn,
                    poll_get_data,
                    cancellable,
                    _poll_get_done_cb,
                    poll_get_data);
}

gboolean
nm_http_client_poll_get_finish(NMHttpClient *self,
                               GAsyncResult *result,
                               long *        out_response_code,
                               GBytes **     out_response_data,
                               GError **     error)
{
    PollGetData * poll_get_data;
    GTask *       task;
    gboolean      success;
    gs_free_error GError *local_error = NULL;

    g_return_val_if_fail(NM_HTTP_CLIENT(self), FALSE);
    g_return_val_if_fail(nm_g_task_is_valid(result, self, nm_http_client_poll_get), FALSE);

    task = G_TASK(result);

    success = g_task_propagate_boolean(task, &local_error);

    nm_assert((!!success) == (!local_error));

    if (local_error) {
        g_propagate_error(error, g_steal_pointer(&local_error));
        NM_SET_OUT(out_response_code, -1);
        NM_SET_OUT(out_response_data, NULL);
        return FALSE;
    }

    poll_get_data = g_task_get_task_data(task);

    NM_SET_OUT(out_response_code, poll_get_data->response_code);
    NM_SET_OUT(out_response_data, g_steal_pointer(&poll_get_data->response_data));
    return TRUE;
}

/*****************************************************************************/

static void
_mhandle_action(NMHttpClient *self, int sockfd, int ev_bitmask)
{
    NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);
    EHandleData *        edata;
    CURLMsg *            msg;
    CURLcode             eret;
    int                  m_left;
    CURLMcode            ret;
    int                  running_handles;

    ret = curl_multi_socket_action(priv->mhandle, sockfd, ev_bitmask, &running_handles);
    if (ret != CURLM_OK) {
        _LOGE("curl: curl_multi_socket_action() failed: (%d) %s", ret, curl_multi_strerror(ret));
        /* really unexpected. Not clear how to handle this. */
    }

    while ((msg = curl_multi_info_read(priv->mhandle, &m_left))) {
        if (msg->msg != CURLMSG_DONE)
            continue;

        eret = curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (char **) &edata);

        nm_assert(eret == CURLE_OK);
        nm_assert(edata);

        edata->ehandle_result = msg->data.result;
        _ehandle_complete(edata, NULL);
    }
}

static gboolean
_mhandle_socket_cb(int fd, GIOCondition condition, gpointer user_data)
{
    int ev_bitmask = 0;

    if (condition & G_IO_IN)
        ev_bitmask |= CURL_CSELECT_IN;
    if (condition & G_IO_OUT)
        ev_bitmask |= CURL_CSELECT_OUT;
    if (condition & G_IO_ERR)
        ev_bitmask |= CURL_CSELECT_ERR;

    _mhandle_action(user_data, fd, ev_bitmask);
    return G_SOURCE_CONTINUE;
}

static int
_mhandle_socketfunction_cb(CURL *        e_handle,
                           curl_socket_t fd,
                           int           what,
                           void *        user_data,
                           void *        socketp)
{
    GSource *            source_socket;
    NMHttpClient *       self = user_data;
    NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

    (void) _NM_ENSURE_TYPE(int, fd);

    g_hash_table_remove(priv->source_sockets_hashtable, GINT_TO_POINTER(fd));

    if (what != CURL_POLL_REMOVE) {
        GIOCondition condition = 0;

        if (what == CURL_POLL_IN)
            condition = G_IO_IN;
        else if (what == CURL_POLL_OUT)
            condition = G_IO_OUT;
        else if (what == CURL_POLL_INOUT)
            condition = G_IO_IN | G_IO_OUT;
        else
            condition = 0;

        if (condition) {
            source_socket = nm_g_unix_fd_source_new(fd,
                                                    condition,
                                                    G_PRIORITY_DEFAULT,
                                                    _mhandle_socket_cb,
                                                    self,
                                                    NULL);
            g_source_attach(source_socket, priv->context);

            g_hash_table_insert(priv->source_sockets_hashtable, GINT_TO_POINTER(fd), source_socket);
        }
    }

    return CURLM_OK;
}

static gboolean
_mhandle_timeout_cb(gpointer user_data)
{
    _mhandle_action(user_data, CURL_SOCKET_TIMEOUT, 0);
    return G_SOURCE_REMOVE;
}

static int
_mhandle_timerfunction_cb(CURLM *multi, long timeout_msec, void *user_data)
{
    NMHttpClient *       self = user_data;
    NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

    nm_clear_pointer(&priv->mhandle_source_timeout, nm_g_source_destroy_and_unref);
    if (timeout_msec >= 0) {
        priv->mhandle_source_timeout =
            _source_attach(self,
                           nm_g_timeout_source_new(NM_MIN(timeout_msec, G_MAXINT),
                                                   G_PRIORITY_DEFAULT,
                                                   _mhandle_timeout_cb,
                                                   self,
                                                   NULL));
    }
    return 0;
}

/*****************************************************************************/

static void
nm_http_client_init(NMHttpClient *self)
{
    NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

    priv->source_sockets_hashtable =
        g_hash_table_new_full(nm_direct_hash,
                              NULL,
                              NULL,
                              (GDestroyNotify) nm_g_source_destroy_and_unref);
}

static void
constructed(GObject *object)
{
    NMHttpClient *       self = NM_HTTP_CLIENT(object);
    NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

    priv->context = g_main_context_ref_thread_default();

    priv->mhandle = curl_multi_init();
    if (!priv->mhandle)
        _LOGE("curl: failed to create multi-handle");
    else {
        curl_multi_setopt(priv->mhandle, CURLMOPT_SOCKETFUNCTION, _mhandle_socketfunction_cb);
        curl_multi_setopt(priv->mhandle, CURLMOPT_SOCKETDATA, self);
        curl_multi_setopt(priv->mhandle, CURLMOPT_TIMERFUNCTION, _mhandle_timerfunction_cb);
        curl_multi_setopt(priv->mhandle, CURLMOPT_TIMERDATA, self);
    }

    G_OBJECT_CLASS(nm_http_client_parent_class)->constructed(object);
}

NMHttpClient *
nm_http_client_new(void)
{
    return g_object_new(NM_TYPE_HTTP_CLIENT, NULL);
}

static void
dispose(GObject *object)
{
    NMHttpClient *       self = NM_HTTP_CLIENT(object);
    NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

    nm_clear_pointer(&priv->mhandle, curl_multi_cleanup);
    nm_clear_pointer(&priv->source_sockets_hashtable, g_hash_table_unref);

    nm_clear_g_source_inst(&priv->mhandle_source_timeout);

    G_OBJECT_CLASS(nm_http_client_parent_class)->dispose(object);
}

static void
finalize(GObject *object)
{
    NMHttpClient *       self = NM_HTTP_CLIENT(object);
    NMHttpClientPrivate *priv = NM_HTTP_CLIENT_GET_PRIVATE(self);

    G_OBJECT_CLASS(nm_http_client_parent_class)->finalize(object);

    g_main_context_unref(priv->context);

    curl_global_cleanup();
}

static void
nm_http_client_class_init(NMHttpClientClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->constructed = constructed;
    object_class->dispose     = dispose;
    object_class->finalize    = finalize;

    nm_http_client_curl_global_init();
}
