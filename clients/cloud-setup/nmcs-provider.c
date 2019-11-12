// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nmcs-provider.h"

#include "nm-cloud-setup-utils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_HTTP_CLIENT,
);

typedef struct _NMCSProviderPrivate {
	NMHttpClient *http_client;
} NMCSProviderPrivate;

G_DEFINE_TYPE (NMCSProvider, nmcs_provider, G_TYPE_OBJECT);

#define NMCS_PROVIDER_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMCSProvider, NMCS_IS_PROVIDER)

/*****************************************************************************/

const char *
nmcs_provider_get_name (NMCSProvider *self)
{
	NMCSProviderClass *klass;

	g_return_val_if_fail (NMCS_IS_PROVIDER (self), NULL);

	klass = NMCS_PROVIDER_GET_CLASS (self);
	nm_assert (klass->_name);
	return klass->_name;
}

/*****************************************************************************/

NMHttpClient *
nmcs_provider_get_http_client (NMCSProvider *self)
{
	g_return_val_if_fail (NMCS_IS_PROVIDER (self), NULL);

	return NMCS_PROVIDER_GET_PRIVATE (self)->http_client;
}

GMainContext *
nmcs_provider_get_main_context (NMCSProvider *self)
{
	g_return_val_if_fail (NMCS_IS_PROVIDER (self), NULL);

	return nm_http_client_get_main_context (NMCS_PROVIDER_GET_PRIVATE (self)->http_client);
}

/*****************************************************************************/

void
nmcs_provider_detect (NMCSProvider *self,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
	gs_unref_object GTask *task = NULL;

	g_return_if_fail (NMCS_IS_PROVIDER (self));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	task = nm_g_task_new (self, cancellable, nmcs_provider_detect, callback, user_data);

	nmcs_wait_for_objects_register (task);

	NMCS_PROVIDER_GET_CLASS (self)->detect (self,
	                                        g_steal_pointer (&task));
}

gboolean
nmcs_provider_detect_finish (NMCSProvider *self,
                             GAsyncResult *result,
                             GError **error)
{
	g_return_val_if_fail (NMCS_IS_PROVIDER (self), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, self, nmcs_provider_detect), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/

NMCSProviderGetConfigIfaceData *
nmcs_provider_get_config_iface_data_new (gboolean was_requested)
{
	NMCSProviderGetConfigIfaceData *iface_data;

	iface_data = g_slice_new (NMCSProviderGetConfigIfaceData);
	*iface_data = (NMCSProviderGetConfigIfaceData) {
		.iface_idx     = -1,
		.was_requested = was_requested,
	};
	return iface_data;
}

static void
_iface_data_free (gpointer data)
{
	NMCSProviderGetConfigIfaceData *iface_data = data;

	g_free (iface_data->ipv4s_arr);

	nm_g_slice_free (iface_data);
}

static void
_get_config_data_free (gpointer data)
{
	NMCSProviderGetConfigTaskData *get_config_data = data;

	if (get_config_data->extra_destroy)
		get_config_data->extra_destroy (get_config_data->extra_data);

	nm_clear_pointer (&get_config_data->result_dict, g_hash_table_unref);

	nm_g_slice_free (get_config_data);
}

void
nmcs_provider_get_config (NMCSProvider *self,
                          gboolean any,
                          const char *const*hwaddrs,
                          GCancellable *cancellable,
                          GAsyncReadyCallback callback,
                          gpointer user_data)
{
	NMCSProviderGetConfigTaskData *get_config_data;

	g_return_if_fail (NMCS_IS_PROVIDER (self));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	get_config_data = g_slice_new (NMCSProviderGetConfigTaskData);
	*get_config_data = (NMCSProviderGetConfigTaskData) {
		.task        = nm_g_task_new (self, cancellable, nmcs_provider_get_config, callback, user_data),
		.any         = any,
		.result_dict = g_hash_table_new_full (nm_str_hash,
		                                      g_str_equal,
		                                      g_free,
		                                      _iface_data_free),
	};

	g_task_set_task_data (get_config_data->task, get_config_data, _get_config_data_free);

	nmcs_wait_for_objects_register (get_config_data->task);

	for (; hwaddrs && hwaddrs[0]; hwaddrs++) {
		g_hash_table_insert (get_config_data->result_dict,
		                     g_strdup (hwaddrs[0]),
		                     nmcs_provider_get_config_iface_data_new (TRUE));
	}

	_LOGD ("get-config: starting");

	NMCS_PROVIDER_GET_CLASS (self)->get_config (self, get_config_data);
}

GHashTable *
nmcs_provider_get_config_finish (NMCSProvider *self,
                                 GAsyncResult *result,
                                 GError **error)
{
	g_return_val_if_fail (NMCS_IS_PROVIDER (self), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, self, nmcs_provider_get_config), FALSE);

	return g_task_propagate_pointer (G_TASK (result), error);
}

/*****************************************************************************/

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMCSProviderPrivate *priv = NMCS_PROVIDER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HTTP_CLIENT:
		priv->http_client = g_value_dup_object (value);
		g_return_if_fail (NM_IS_HTTP_CLIENT (priv->http_client));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nmcs_provider_init (NMCSProvider *self)
{
	NMCSProviderPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NMCS_TYPE_PROVIDER, NMCSProviderPrivate);

	self->_priv = priv;
}

static void
dispose (GObject *object)
{
	NMCSProvider *self = NMCS_PROVIDER (object);
	NMCSProviderPrivate *priv = NMCS_PROVIDER_GET_PRIVATE (self);

	g_clear_object (&priv->http_client);

	G_OBJECT_CLASS (nmcs_provider_parent_class)->dispose (object);
}

static void
nmcs_provider_class_init (NMCSProviderClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMCSProviderPrivate));

	object_class->set_property = set_property;
	object_class->dispose      = dispose;

	obj_properties[PROP_HTTP_CLIENT] =
	    g_param_spec_object (NMCS_PROVIDER_HTTP_CLIENT, "", "",
	                         NM_TYPE_HTTP_CLIENT,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
