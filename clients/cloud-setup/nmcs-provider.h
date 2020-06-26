// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NMCS_PROVIDER_H__
#define __NMCS_PROVIDER_H__

/*****************************************************************************/

#include "nm-http-client.h"

/*****************************************************************************/

typedef struct {
	in_addr_t *ipv4s_arr;
	gsize ipv4s_len;
	gssize iface_idx;
	in_addr_t cidr_addr;
	guint8 cidr_prefix;
	bool has_ipv4s:1;
	bool has_cidr:1;

	NMIPRoute **iproutes_arr;
	gsize iproutes_len;

	/* TRUE, if the configuration was requested via hwaddrs argument to
	 * nmcs_provider_get_config(). */
	bool was_requested:1;

} NMCSProviderGetConfigIfaceData;

static inline gboolean
nmcs_provider_get_config_iface_data_is_valid (const NMCSProviderGetConfigIfaceData *config_data)
{
	return    config_data
	       && config_data->iface_idx >= 0
	       && (   (   config_data->has_ipv4s
	               && config_data->has_cidr)
	           || config_data->iproutes_len);
}

NMCSProviderGetConfigIfaceData *nmcs_provider_get_config_iface_data_new (gboolean was_requested);

typedef struct {
	GTask *task;
	GHashTable *result_dict;
	gpointer extra_data;
	GDestroyNotify extra_destroy;
	bool any:1;
} NMCSProviderGetConfigTaskData;

#define NMCS_TYPE_PROVIDER            (nmcs_provider_get_type ())
#define NMCS_PROVIDER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMCS_TYPE_PROVIDER, NMCSProvider))
#define NMCS_PROVIDER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMCS_TYPE_PROVIDER, NMCSProviderClass))
#define NMCS_IS_PROVIDER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMCS_TYPE_PROVIDER))
#define NMCS_IS_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMCS_TYPE_PROVIDER))
#define NMCS_PROVIDER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMCS_TYPE_PROVIDER, NMCSProviderClass))

#define NMCS_PROVIDER_HTTP_CLIENT "http-client"

struct _NMCSProviderPrivate;

typedef struct {
	GObject parent;
	struct _NMCSProviderPrivate *_priv;
} NMCSProvider;

typedef struct {
	GObjectClass parent;
	const char *_name;
	const char *_env_provider_enabled;

	void (*detect) (NMCSProvider *self,
	                GTask *task);

	void (*get_config) (NMCSProvider *self,
	                    NMCSProviderGetConfigTaskData *get_config_data);

} NMCSProviderClass;

GType nmcs_provider_get_type (void);

/*****************************************************************************/

const char *nmcs_provider_get_name (NMCSProvider *provider);

NMHttpClient *nmcs_provider_get_http_client (NMCSProvider *provider);
GMainContext *nmcs_provider_get_main_context (NMCSProvider *provider);

/*****************************************************************************/

void nmcs_provider_detect (NMCSProvider *provider,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data);

gboolean nmcs_provider_detect_finish (NMCSProvider *provider,
                                      GAsyncResult *result,
                                      GError **error);

/*****************************************************************************/

void nmcs_provider_get_config (NMCSProvider *provider,
                               gboolean any,
                               const char *const*hwaddrs,
                               GCancellable *cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data);

GHashTable *nmcs_provider_get_config_finish (NMCSProvider *provider,
                                             GAsyncResult *result,
                                             GError **error);

#endif /* __NMCS_PROVIDER_H__ */
