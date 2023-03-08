/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_HTTP_CLIENT_C__
#define __NM_HTTP_CLIENT_C__

/*****************************************************************************/

typedef struct _NMHttpClient      NMHttpClient;
typedef struct _NMHttpClientClass NMHttpClientClass;

#define NM_TYPE_HTTP_CLIENT (nm_http_client_get_type())
#define NM_HTTP_CLIENT(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_HTTP_CLIENT, NMHttpClient))
#define NM_HTTP_CLIENT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_HTTP_CLIENT, NMHttpClientClass))
#define NM_IS_HTTP_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_HTTP_CLIENT))
#define NM_IS_HTTP_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_HTTP_CLIENT))
#define NM_HTTP_CLIENT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_HTTP_CLIENT, NMHttpClientClass))

GType nm_http_client_get_type(void);

NMHttpClient *nm_http_client_new(void);

/*****************************************************************************/

GMainContext *nm_http_client_get_main_context(NMHttpClient *self);

/*****************************************************************************/

typedef gboolean (*NMHttpClientPollReqCheckFcn)(long     response_code,
                                                GBytes  *response_data,
                                                gpointer check_user_data,
                                                GError **error);

void nm_http_client_poll_req(NMHttpClient               *self,
                             const char                 *uri,
                             int                         request_timeout_ms,
                             gssize                      request_max_data,
                             int                         poll_timeout_ms,
                             int                         ratelimit_timeout_ms,
                             const char *const          *http_headers,
                             const char                 *http_method,
                             GCancellable               *cancellable,
                             NMHttpClientPollReqCheckFcn check_fcn,
                             gpointer                    check_user_data,
                             GAsyncReadyCallback         callback,
                             gpointer                    user_data);

gboolean nm_http_client_poll_req_finish(NMHttpClient *self,
                                        GAsyncResult *result,
                                        long         *out_response_code,
                                        GBytes      **out_response_data,
                                        GError      **error);

/*****************************************************************************/

#endif /* __NM_HTTP_CLIENT_C__ */
