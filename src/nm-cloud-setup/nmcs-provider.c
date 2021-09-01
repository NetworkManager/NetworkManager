/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmcs-provider.h"

#include "nm-cloud-setup-utils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_HTTP_CLIENT, );

typedef struct _NMCSProviderPrivate {
    NMHttpClient *http_client;
} NMCSProviderPrivate;

G_DEFINE_TYPE(NMCSProvider, nmcs_provider, G_TYPE_OBJECT);

#define NMCS_PROVIDER_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMCSProvider, NMCS_IS_PROVIDER)

/*****************************************************************************/

const char *
nmcs_provider_get_name(NMCSProvider *self)
{
    NMCSProviderClass *klass;

    g_return_val_if_fail(NMCS_IS_PROVIDER(self), NULL);

    klass = NMCS_PROVIDER_GET_CLASS(self);
    nm_assert(klass->_name);
    return klass->_name;
}

/*****************************************************************************/

NMHttpClient *
nmcs_provider_get_http_client(NMCSProvider *self)
{
    g_return_val_if_fail(NMCS_IS_PROVIDER(self), NULL);

    return NMCS_PROVIDER_GET_PRIVATE(self)->http_client;
}

GMainContext *
nmcs_provider_get_main_context(NMCSProvider *self)
{
    g_return_val_if_fail(NMCS_IS_PROVIDER(self), NULL);

    return nm_http_client_get_main_context(NMCS_PROVIDER_GET_PRIVATE(self)->http_client);
}
/*****************************************************************************/

static int
_result_new_sort_iface_data(gconstpointer pa, gconstpointer pb)
{
    const NMCSProviderGetConfigIfaceData *a = *((const NMCSProviderGetConfigIfaceData *const *) pa);
    const NMCSProviderGetConfigIfaceData *b = *((const NMCSProviderGetConfigIfaceData *const *) pb);

    /* negative iface_idx are sorted to the end. */
    NM_CMP_DIRECT((a->iface_idx < 0), (b->iface_idx < 0));

    NM_CMP_FIELD(a, b, iface_idx);
    return 0;
}

static NMCSProviderGetConfigResult *
nmcs_provider_get_config_result_new(GHashTable *iface_datas)
{
    const NMCSProviderGetConfigIfaceData *iface_data;
    NMCSProviderGetConfigResult *         result;
    GHashTableIter                        h_iter;
    guint                                 num_valid_ifaces = 0;
    guint                                 num_ipv4s        = 0;
    GPtrArray *                           ptrarr;
    guint                                 n_iface_datas;

    n_iface_datas = g_hash_table_size(iface_datas);

    ptrarr = g_ptr_array_sized_new(n_iface_datas + 1u);

    g_hash_table_iter_init(&h_iter, iface_datas);
    while (g_hash_table_iter_next(&h_iter, NULL, (gpointer *) &iface_data)) {
        if (nmcs_provider_get_config_iface_data_is_valid(iface_data)) {
            num_valid_ifaces++;
            num_ipv4s += iface_data->ipv4s_len;
        }
        g_ptr_array_add(ptrarr, (gpointer) iface_data);
    }

    g_ptr_array_sort(ptrarr, _result_new_sort_iface_data);

    nm_assert(n_iface_datas == ptrarr->len);

    g_ptr_array_add(ptrarr, NULL);

    result  = g_new(NMCSProviderGetConfigResult, 1);
    *result = (NMCSProviderGetConfigResult){
        .iface_datas   = g_hash_table_ref(iface_datas),
        .n_iface_datas = n_iface_datas,
        .iface_datas_arr =
            (const NMCSProviderGetConfigIfaceData **) g_ptr_array_free(ptrarr, FALSE),
        .num_valid_ifaces = num_valid_ifaces,
        .num_ipv4s        = num_ipv4s,
    };

#if NM_MORE_ASSERTS > 5
    {
        gsize iface_idx_expected = 0;
        guint i;

        for (i = 0; i < result->n_iface_datas; i++) {
            if (result->iface_datas_arr[i]->iface_idx < 0) {
                nm_assert(result->iface_datas_arr[i]->iface_idx == -1);
                iface_idx_expected = -1;
                continue;
            }
            nm_assert(result->iface_datas_arr[i]->iface_idx == iface_idx_expected);
            iface_idx_expected++;
        }
    }
#endif

    return result;
}

void
nmcs_provider_get_config_result_free(NMCSProviderGetConfigResult *result)
{
    if (result) {
        nm_g_hash_table_unref(result->iface_datas);
        g_free((gpointer) result->iface_datas_arr);
        g_free(result);
    }
}

/*****************************************************************************/

void
nmcs_provider_detect(NMCSProvider *      self,
                     GCancellable *      cancellable,
                     GAsyncReadyCallback callback,
                     gpointer            user_data)
{
    gs_unref_object GTask *task = NULL;
    const char *           env;

    g_return_if_fail(NMCS_IS_PROVIDER(self));
    g_return_if_fail(!cancellable || G_IS_CANCELLABLE(cancellable));

    task = nm_g_task_new(self, cancellable, nmcs_provider_detect, callback, user_data);

    nmcs_wait_for_objects_register(task);

    env = g_getenv(NMCS_PROVIDER_GET_CLASS(self)->_env_provider_enabled);
    if (!_nm_utils_ascii_str_to_bool(env, FALSE)) {
        g_task_return_error(task,
                            nm_utils_error_new(NM_UTILS_ERROR_UNKNOWN, "provider is disabled"));
        return;
    }

    NMCS_PROVIDER_GET_CLASS(self)->detect(self, g_steal_pointer(&task));
}

gboolean
nmcs_provider_detect_finish(NMCSProvider *self, GAsyncResult *result, GError **error)
{
    g_return_val_if_fail(NMCS_IS_PROVIDER(self), FALSE);
    g_return_val_if_fail(nm_g_task_is_valid(result, self, nmcs_provider_detect), FALSE);

    return g_task_propagate_boolean(G_TASK(result), error);
}

/*****************************************************************************/

NMCSProviderGetConfigIfaceData *
nmcs_provider_get_config_iface_data_create(GHashTable *iface_datas,
                                           gboolean    was_requested,
                                           const char *hwaddr)
{
    NMCSProviderGetConfigIfaceData *iface_data;

    nm_assert(hwaddr);

    iface_data  = g_slice_new(NMCSProviderGetConfigIfaceData);
    *iface_data = (NMCSProviderGetConfigIfaceData){
        .hwaddr        = g_strdup(hwaddr),
        .iface_idx     = -1,
        .was_requested = was_requested,
    };

    /* the has does not own the key (iface_datta->hwaddr), the lifetime of the
     * key is associated with the iface_data instance. */
    g_hash_table_replace(iface_datas, (char *) iface_data->hwaddr, iface_data);

    return iface_data;
}

static void
_iface_data_free(gpointer data)
{
    NMCSProviderGetConfigIfaceData *iface_data = data;

    g_free(iface_data->ipv4s_arr);
    g_free(iface_data->iproutes_arr);
    g_free((char *) iface_data->hwaddr);

    nm_g_slice_free(iface_data);
}

static void
_get_config_task_maybe_return(NMCSProviderGetConfigTaskData *get_config_data, GError *error_take)
{
    gs_free_error GError *error = error_take;

    nm_assert(get_config_data);
    nm_assert(G_IS_TASK(get_config_data->task));

    if (!error) {
        if (get_config_data->n_pending > 0)
            return;
    }

    g_cancellable_cancel(get_config_data->intern_cancellable);

    if (error) {
        if (nm_utils_error_is_cancelled(error))
            _LOGD("get-config: cancelled");
        else
            _LOGD("get-config: failed: %s", error->message);
        g_task_return_error(get_config_data->task, g_steal_pointer(&error));
    } else {
        _LOGD("get-config: success");
        g_task_return_pointer(get_config_data->task,
                              nmcs_provider_get_config_result_new(get_config_data->result_dict),
                              (GDestroyNotify) nmcs_provider_get_config_result_free);
    }

    nm_clear_g_signal_handler(g_task_get_cancellable(get_config_data->task),
                              &get_config_data->extern_cancelled_id);

    if (get_config_data->extra_data_destroy)
        get_config_data->extra_data_destroy(get_config_data->extra_data);

    nm_clear_pointer(&get_config_data->result_dict, g_hash_table_unref);

    nm_g_object_unref(get_config_data->intern_cancellable);
    g_object_unref(get_config_data->task);
    nm_g_slice_free(get_config_data);
}

void
_nmcs_provider_get_config_task_maybe_return(NMCSProviderGetConfigTaskData *get_config_data,
                                            GError *                       error_take)
{
    nm_assert(!error_take || !nm_utils_error_is_cancelled(error_take));
    _get_config_task_maybe_return(get_config_data, error_take);
}

static void
_get_config_cancelled_cb(GObject *object, gpointer user_data)
{
    _get_config_task_maybe_return(user_data, nm_utils_error_new_cancelled(FALSE, NULL));
}

void
nmcs_provider_get_config(NMCSProvider *      self,
                         gboolean            any,
                         const char *const * hwaddrs,
                         GCancellable *      cancellable,
                         GAsyncReadyCallback callback,
                         gpointer            user_data)
{
    NMCSProviderGetConfigTaskData *get_config_data;

    g_return_if_fail(NMCS_IS_PROVIDER(self));
    g_return_if_fail(!cancellable || G_IS_CANCELLABLE(cancellable));

    _LOGD("get-config: starting");

    get_config_data  = g_slice_new(NMCSProviderGetConfigTaskData);
    *get_config_data = (NMCSProviderGetConfigTaskData){
        .task = nm_g_task_new(self, cancellable, nmcs_provider_get_config, callback, user_data),
        .any  = any,
        .result_dict = g_hash_table_new_full(nm_str_hash, g_str_equal, NULL, _iface_data_free),
    };

    nmcs_wait_for_objects_register(get_config_data->task);

    for (; hwaddrs && hwaddrs[0]; hwaddrs++)
        nmcs_provider_get_config_iface_data_create(get_config_data->result_dict, TRUE, hwaddrs[0]);

    if (cancellable) {
        gulong cancelled_id;

        cancelled_id = g_cancellable_connect(cancellable,
                                             G_CALLBACK(_get_config_cancelled_cb),
                                             get_config_data,
                                             NULL);
        if (cancelled_id == 0) {
            /* the callback was already invoked synchronously and the task already returned. */
            return;
        }

        get_config_data->extern_cancelled_id = cancelled_id;
        get_config_data->intern_cancellable  = g_cancellable_new();
    }

    NMCS_PROVIDER_GET_CLASS(self)->get_config(self, get_config_data);
}

NMCSProviderGetConfigResult *
nmcs_provider_get_config_finish(NMCSProvider *self, GAsyncResult *result, GError **error)
{
    g_return_val_if_fail(NMCS_IS_PROVIDER(self), FALSE);
    g_return_val_if_fail(nm_g_task_is_valid(result, self, nmcs_provider_get_config), FALSE);

    return g_task_propagate_pointer(G_TASK(result), error);
}

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMCSProviderPrivate *priv = NMCS_PROVIDER_GET_PRIVATE(object);

    switch (prop_id) {
    case PROP_HTTP_CLIENT:
        priv->http_client = g_value_dup_object(value);
        g_return_if_fail(NM_IS_HTTP_CLIENT(priv->http_client));
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nmcs_provider_init(NMCSProvider *self)
{
    NMCSProviderPrivate *priv;

    priv = G_TYPE_INSTANCE_GET_PRIVATE(self, NMCS_TYPE_PROVIDER, NMCSProviderPrivate);

    self->_priv = priv;
}

static void
dispose(GObject *object)
{
    NMCSProvider *       self = NMCS_PROVIDER(object);
    NMCSProviderPrivate *priv = NMCS_PROVIDER_GET_PRIVATE(self);

    g_clear_object(&priv->http_client);

    G_OBJECT_CLASS(nmcs_provider_parent_class)->dispose(object);
}

static void
nmcs_provider_class_init(NMCSProviderClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    g_type_class_add_private(object_class, sizeof(NMCSProviderPrivate));

    object_class->set_property = set_property;
    object_class->dispose      = dispose;

    obj_properties[PROP_HTTP_CLIENT] =
        g_param_spec_object(NMCS_PROVIDER_HTTP_CLIENT,
                            "",
                            "",
                            NM_TYPE_HTTP_CLIENT,
                            G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
