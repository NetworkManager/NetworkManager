// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_HTTP_CLIENT_C__
#define __NM_HTTP_CLIENT_C__

/*****************************************************************************/

typedef struct _NMHttpClient      NMHttpClient;
typedef struct _NMHttpClientClass NMHttpClientClass;

#define NM_TYPE_HTTP_CLIENT            (nm_http_client_get_type ())
#define NM_HTTP_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HTTP_CLIENT, NMHttpClient))
#define NM_HTTP_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_HTTP_CLIENT, NMHttpClientClass))
#define NM_IS_HTTP_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HTTP_CLIENT))
#define NM_IS_HTTP_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_HTTP_CLIENT))
#define NM_HTTP_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_HTTP_CLIENT, NMHttpClientClass))

GType nm_http_client_get_type (void);

NMHttpClient *nm_http_client_new (void);

/*****************************************************************************/

GMainContext *nm_http_client_get_main_context (NMHttpClient *self);

/*****************************************************************************/

void nm_http_client_get (NMHttpClient *self,
                         const char *uri,
                         int timeout_ms,
                         gssize max_data,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data);

gboolean nm_http_client_get_finish (NMHttpClient *self,
                                    GAsyncResult *result,
                                    long *out_response_code,
                                    GBytes **out_response_data,
                                    GError **error);

typedef gboolean (*NMHttpClientPollGetCheckFcn) (long response_code,
                                                 GBytes *response_data,
                                                 gpointer check_user_data,
                                                 GError **error);

void nm_http_client_poll_get (NMHttpClient *self,
                              const char *uri,
                              int request_timeout_ms,
                              gssize request_max_data,
                              int poll_timeout_ms,
                              int ratelimit_timeout_ms,
                              GCancellable *cancellable,
                              NMHttpClientPollGetCheckFcn check_fcn,
                              gpointer check_user_data,
                              GAsyncReadyCallback callback,
                              gpointer user_data);

gboolean nm_http_client_poll_get_finish (NMHttpClient *self,
                                         GAsyncResult *result,
                                         long *out_response_code,
                                         GBytes **out_response_data,
                                         GError **error);

/*****************************************************************************/

#endif /* __NM_HTTP_CLIENT_C__ */
