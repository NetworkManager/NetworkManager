/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NMCS_PROVIDER_H__
#define __NMCS_PROVIDER_H__

/*****************************************************************************/

#include "nm-http-client.h"

/*****************************************************************************/

struct _NMCSProvider;
struct _NMCSProviderGetConfigTaskData;

typedef struct {
    /* And it's exactly the same pointer that is also the key for the iface_datas
     * dictionary. */
    const char *hwaddr;

    struct _NMCSProviderGetConfigTaskData *get_config_data;

    in_addr_t *ipv4s_arr;
    gsize      ipv4s_len;

    /* If the interface was seen, get_config() should set this to a
     * unique, increasing, positive index. If the interface is requested,
     * it is initialized to -1. */
    gssize iface_idx;

    in_addr_t cidr_addr;
    in_addr_t gateway;
    guint8    cidr_prefix;
    bool      has_ipv4s : 1;
    bool      has_cidr : 1;
    bool      has_gateway : 1;

    /* Array of NMIPRoute (must own/free the entries). */
    GPtrArray *iproutes;

    /* TRUE, if the configuration was requested via hwaddrs argument to
     * nmcs_provider_get_config(). */
    bool was_requested : 1;

    /* Usually we would want that the parent class NMCSProvider is not aware about
     * the implementations. However, it's convenient to track implementation specific data
     * here, thus we violate such separation. In practice, all subclasses are known
     * at compile time, and it will be simpler this way. */
    union {
        struct {
            in_addr_t primary_ip_address;
            bool      has_primary_ip_address : 1;
            bool      ipv4s_arr_ordered : 1;
        } aliyun;
    } priv;

} NMCSProviderGetConfigIfaceData;

static inline gboolean
nmcs_provider_get_config_iface_data_is_valid(const NMCSProviderGetConfigIfaceData *config_data)
{
    return config_data && config_data->iface_idx >= 0
           && ((config_data->has_ipv4s && config_data->has_cidr)
               || nm_g_ptr_array_len(config_data->iproutes) > 0);
}

/*****************************************************************************/

typedef struct {
    /* A dictionary of (const char *) -> (NMCSProviderGetConfigIfaceData *).
     * This is the per-interface result of get_config().
     *
     * The key is the same pointer as NMCSProviderGetConfigIfaceData's hwaddr. */
    GHashTable *iface_datas;

    /* The number of iface_datas that are nmcs_provider_get_config_iface_data_is_valid(). */
    guint num_valid_ifaces;

    /* the number of IPv4 addresses over all valid iface_datas. */
    guint num_ipv4s;

    guint n_iface_datas;

    /* The sorted value of @iface_datas, sorted by iface_idx.
     *
     * Not found entries (iface_idx == -1) are sorted at the end. */
    const NMCSProviderGetConfigIfaceData *const *iface_datas_arr;

} NMCSProviderGetConfigResult;

void nmcs_provider_get_config_result_free(NMCSProviderGetConfigResult *result);

NM_AUTO_DEFINE_FCN0(NMCSProviderGetConfigResult *,
                    _nm_auto_free_nmcs_provider_get_config_result,
                    nmcs_provider_get_config_result_free);
#define nm_auto_free_nmcs_provider_get_config_result \
    nm_auto(_nm_auto_free_nmcs_provider_get_config_result)

/*****************************************************************************/

typedef struct _NMCSProviderGetConfigTaskData {
    GTask *task;

    struct _NMCSProvider *self;

    GHashTable *result_dict;

    /* this cancellable should be used for the provider implementation
     * to listen for cancellation. */
    GCancellable *intern_cancellable;

    /* the provider implementation may attach extra data. */
    gpointer       extra_data;
    GDestroyNotify extra_data_destroy;

    gulong extern_cancelled_id;

    /* the provider implementation may use this field to track the number of pending
     * operations. */
    guint n_pending;

    bool any : 1;
} NMCSProviderGetConfigTaskData;

/*****************************************************************************/

NMCSProviderGetConfigIfaceData *
nmcs_provider_get_config_iface_data_create(NMCSProviderGetConfigTaskData *get_config_data,
                                           gboolean                       was_requested,
                                           const char                    *hwaddr);

/*****************************************************************************/

#define NMCS_TYPE_PROVIDER (nmcs_provider_get_type())
#define NMCS_PROVIDER(obj) (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMCS_TYPE_PROVIDER, NMCSProvider))
#define NMCS_PROVIDER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMCS_TYPE_PROVIDER, NMCSProviderClass))
#define NMCS_IS_PROVIDER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMCS_TYPE_PROVIDER))
#define NMCS_IS_PROVIDER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMCS_TYPE_PROVIDER))
#define NMCS_PROVIDER_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMCS_TYPE_PROVIDER, NMCSProviderClass))

#define NMCS_PROVIDER_HTTP_CLIENT "http-client"

struct _NMCSProviderPrivate;

typedef struct _NMCSProvider {
    GObject                      parent;
    struct _NMCSProviderPrivate *_priv;
} NMCSProvider;

typedef struct {
    GObjectClass parent;
    const char  *_name;
    const char  *_env_provider_enabled;

    /**
     * detect:
     * @self: the #NMCSProvider
     * @task: a #GTask that's completed when the detection finishes.
     *
     * Checks whether the metadata of a particular cloud provider is
     * accessible on the host machine. The check runs asynchronously.
     *
     * When the check finishes, @task is completed. If the check was
     * successful, @task returns a gboolean of %TRUE. Otherwise
     * a %FALSE value or an error is returned.
     *
     * The routine has to be called before the get_config() can be
     * used.
     */
    void (*detect)(NMCSProvider *self, GTask *task);

    /**
     * get_config:
     * @self: the #NMCSProvider
     * @get_config_data: encapsulates a #GTask and network configuration data
     *
     * Collects the network configuration from metadata service of a
     * particular cloud provider. The metadata is traversed and checked
     * asynchronously, completing a task encapsulated in @get_config_data
     * upon finishing.
     *
     * Call to detect() with a successful result is necessary before
     * using this routine.
     */
    void (*get_config)(NMCSProvider *self, NMCSProviderGetConfigTaskData *get_config_data);

} NMCSProviderClass;

GType nmcs_provider_get_type(void);

/*****************************************************************************/

const char *nmcs_provider_get_name(NMCSProvider *provider);

NMHttpClient *nmcs_provider_get_http_client(NMCSProvider *provider);
GMainContext *nmcs_provider_get_main_context(NMCSProvider *provider);

/*****************************************************************************/

void nmcs_provider_detect(NMCSProvider       *provider,
                          GCancellable       *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer            user_data);

gboolean nmcs_provider_detect_finish(NMCSProvider *provider, GAsyncResult *result, GError **error);

/*****************************************************************************/

void _nmcs_provider_get_config_task_maybe_return(NMCSProviderGetConfigTaskData *get_config_data,
                                                 GError                        *error_take);

void nmcs_provider_get_config(NMCSProvider       *provider,
                              gboolean            any,
                              const char *const  *hwaddrs,
                              GCancellable       *cancellable,
                              GAsyncReadyCallback callback,
                              gpointer            user_data);

NMCSProviderGetConfigResult *
nmcs_provider_get_config_finish(NMCSProvider *provider, GAsyncResult *result, GError **error);

/*****************************************************************************/

/* Forward declare the implemented gtype getters so we can use it at a few places without requiring
 * to include the full header. The other parts of those headers should not be used aside where they
 * are necessary. */
GType nmcs_provider_aliyun_get_type(void);

#endif /* __NMCS_PROVIDER_H__ */
