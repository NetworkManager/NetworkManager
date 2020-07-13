// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nmcs-provider-azure.h"

#include "nm-cloud-setup-utils.h"

/*****************************************************************************/

#define HTTP_TIMEOUT_MS 3000

#define NM_AZURE_METADATA_HEADER    "Metadata:true"
#define NM_AZURE_HOST               "localhost:8080"
#define NM_AZURE_BASE               "http://" NM_AZURE_HOST
#define NM_AZURE_API_VERSION        "?format=text&api-version=2017-04-02"
#define NM_AZURE_METADATA_URL_BASE  /* $NM_AZURE_BASE/$NM_AZURE_API_VERSION */ "/metadata/instance/network/interface/"

#define _azure_uri_concat(...)     nmcs_utils_uri_build_concat (NM_AZURE_BASE, __VA_ARGS__, NM_AZURE_API_VERSION)
#define _azure_uri_interfaces(...) _azure_uri_concat (NM_AZURE_METADATA_URL_BASE, ##__VA_ARGS__)

/*****************************************************************************/

struct _NMCSProviderAzure {
	NMCSProvider parent;
};

struct _NMCSProviderAzureClass {
	NMCSProviderClass parent;
};

G_DEFINE_TYPE (NMCSProviderAzure, nmcs_provider_azure, NMCS_TYPE_PROVIDER);

/*****************************************************************************/

static void
_detect_get_meta_data_done_cb (GObject *source,
                               GAsyncResult *result,
                               gpointer user_data)
{
	gs_unref_object GTask *task = user_data;
	gs_free_error GError *get_error = NULL;
	gs_free_error GError *error = NULL;
	gboolean success;

	success = nm_http_client_poll_get_finish (NM_HTTP_CLIENT (source),
	                                          result,
	                                          NULL,
	                                          NULL,
	                                          &get_error);

	if (nm_utils_error_is_cancelled (get_error)) {
		g_task_return_error (task, g_steal_pointer (&get_error));
		return;
	}

	if (get_error) {
		nm_utils_error_set (&error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "failure to get Azure metadata: %s",
		                    get_error->message);
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	if (!success) {
		nm_utils_error_set (&error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "failure to detect azure metadata");
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	g_task_return_boolean (task, TRUE);
}

static void
detect (NMCSProvider *provider,
        GTask *task)
{
	NMHttpClient *http_client;
	gs_free char *uri = NULL;

	http_client = nmcs_provider_get_http_client (provider);

	nm_http_client_poll_get (http_client,
	                         (uri = _azure_uri_concat ("/metadata/instance")),
	                         HTTP_TIMEOUT_MS,
	                         256*1024,
	                         7000,
	                         1000,
	                         NM_MAKE_STRV (NM_AZURE_METADATA_HEADER),
	                         g_task_get_cancellable (task),
	                         NULL,
	                         NULL,
	                         _detect_get_meta_data_done_cb,
	                         task);
}

/*****************************************************************************/

typedef struct {
	NMCSProviderGetConfigTaskData *config_data;
	guint n_ifaces_pending;
	GError *error;
	bool success:1;
} AzureData;

typedef struct {
	NMCSProviderGetConfigIfaceData *iface_get_config;
	AzureData *azure_data;
	gssize iface_idx;
	guint n_ips_prefix_pending;
	char *hwaddr;
} AzureIfaceData;

static void
_azure_iface_data_free (AzureIfaceData *iface_data)
{
	g_free(iface_data->hwaddr);
	nm_g_slice_free (iface_data);
}

static void
_get_config_maybe_task_return (AzureData *azure_data,
                               GError *error_take)
{
	NMCSProviderGetConfigTaskData *config_data =  azure_data->config_data;
	gs_free_error GError *azure_error = NULL;

	if (error_take) {
		nm_clear_error (&azure_data->error);
		azure_data->error = error_take;
	}

	if (azure_data->n_ifaces_pending > 0)
		return;

	azure_error = azure_data->error;

	if (azure_error) {
		if (nm_utils_error_is_cancelled (azure_error))
			_LOGD ("get-config: cancelled");
		else
			_LOGD ("get-config: failed: %s", azure_error->message);
		g_task_return_error (config_data->task, g_steal_pointer (&azure_error));
	} else {
		_LOGD ("get-config: success");
		g_task_return_pointer (config_data->task,
		                       g_hash_table_ref (config_data->result_dict),
		                       (GDestroyNotify) g_hash_table_unref);
	}
	nm_g_slice_free (azure_data);
	g_object_unref (config_data->task);
}

static void
_get_config_fetch_done_cb (NMHttpClient *http_client,
                           GAsyncResult *result,
                           gpointer user_data,
                           gboolean is_ipv4)
{
	NMCSProviderGetConfigIfaceData *iface_get_config;
	gs_unref_bytes GBytes *response = NULL;
	AzureIfaceData *iface_data = user_data;
	gs_free_error GError *error = NULL;
	const char *fip_str = NULL;
	AzureData *azure_data;

	azure_data = iface_data->azure_data;

	nm_http_client_poll_get_finish (http_client,
	                                result,
	                                NULL,
	                                &response,
	                                &error);

	if (error)
		goto done;

	if(!error){
		in_addr_t tmp_addr;
		int tmp_prefix;

		fip_str = g_bytes_get_data (response, NULL);
		iface_data->iface_get_config = g_hash_table_lookup (azure_data->config_data->result_dict,
		                                                    iface_data->hwaddr);
		iface_get_config = iface_data->iface_get_config;
		iface_get_config->iface_idx = iface_data->iface_idx;

		if (is_ipv4) {
			if (!nm_utils_parse_inaddr_bin (AF_INET,
			                               fip_str,
			                               NULL,
			                               &tmp_addr)) {
				error = nm_utils_error_new (NM_UTILS_ERROR_UNKNOWN,
				                            "ip is not a valid private ip address");
				goto done;
			}
			_LOGD ("interface[%"G_GSSIZE_FORMAT"]: adding private ip %s",
			       iface_data->iface_idx,
			       fip_str);
			iface_get_config->ipv4s_arr[iface_get_config->ipv4s_len] = tmp_addr;
			iface_get_config->has_ipv4s = TRUE;
			iface_get_config->ipv4s_len++;
		} else {
			tmp_prefix = (_nm_utils_ascii_str_to_int64 (fip_str, 10, 0, 32, -1));

			if (tmp_prefix == -1) {
				_LOGD ("interface[%"G_GSSIZE_FORMAT"]: invalid prefix %d",
				       iface_data->iface_idx,
				       tmp_prefix);
				goto done;
			}
			_LOGD ("interface[%"G_GSSIZE_FORMAT"]: adding prefix %d",
			       iface_data->iface_idx,
			       tmp_prefix);
			iface_get_config->cidr_prefix = tmp_prefix;
			iface_get_config->has_cidr = TRUE;
		}
		azure_data->success = TRUE;
	}

done:
	--iface_data->n_ips_prefix_pending;
	if (iface_data->n_ips_prefix_pending == 0) {
		_azure_iface_data_free (iface_data);
		--azure_data->n_ifaces_pending;
		_get_config_maybe_task_return (azure_data, g_steal_pointer (&error));
	}
}

static void
_get_config_fetch_done_cb_private_ipv4s (GObject *source,
                                         GAsyncResult *result,
                                         gpointer user_data)
{
	_get_config_fetch_done_cb (NM_HTTP_CLIENT (source), result, user_data, TRUE);
}

static void
_get_config_fetch_done_cb_subnet_cidr_prefix (GObject *source,
                                               GAsyncResult *result,
                                               gpointer user_data)
{
	_get_config_fetch_done_cb (NM_HTTP_CLIENT (source), result, user_data, FALSE);
}

static void
_get_config_ips_prefix_list_cb (GObject *source,
                                GAsyncResult *result,
                                gpointer user_data)
{
	gs_unref_bytes GBytes *response = NULL;
	AzureIfaceData *iface_data = user_data;
	gs_free_error GError *error = NULL;
	const char *response_str = NULL;
	gsize response_len;
	AzureData *azure_data;
	const char *line;
	gsize line_len;

	azure_data = iface_data->azure_data;

	nm_http_client_poll_get_finish (NM_HTTP_CLIENT (source),
	                                result,
	                                NULL,
	                                &response,
	                                &error);
	if (error)
		goto done;

	response_str = g_bytes_get_data (response, &response_len);
	/* NMHttpClient guarantees that there is a trailing NUL after the data. */
	nm_assert (response_str[response_len] == 0);

	nm_assert (!iface_data->iface_get_config->has_ipv4s);
	nm_assert (!iface_data->iface_get_config->ipv4s_arr);
	nm_assert (!iface_data->iface_get_config->has_cidr);

	while (nm_utils_parse_next_line (&response_str,
	                                 &response_len,
	                                 &line,
	                                 &line_len)) {
		gint64 ips_prefix_idx;

		if (line_len == 0)
			continue;
		/* Truncate the string. It's safe to do, because we own @response_data an it has an
		 * extra NULL character after the buffer. */
		((char *) line)[line_len] = '\0';

		if (line[line_len - 1] == '/')
			((char *) line)[--line_len] = '\0';

		ips_prefix_idx = _nm_utils_ascii_str_to_int64 (line, 10, 0, G_MAXINT64, -1);

		if (ips_prefix_idx < 0)
			continue;

		{
			gs_free const char *uri = NULL;
			char buf[100];

			iface_data->n_ips_prefix_pending++;

			nm_http_client_poll_get (NM_HTTP_CLIENT (source),
			                         (uri = _azure_uri_interfaces (nm_sprintf_buf (buf,"%"G_GSSIZE_FORMAT"/ipv4/ipAddress/%"G_GINT64_FORMAT"/privateIpAddress",
			                                                                       iface_data->iface_idx,
			                                                                       ips_prefix_idx))),
			                         HTTP_TIMEOUT_MS,
			                         512*1024,
			                         10000,
			                         1000,
			                         NM_MAKE_STRV (NM_AZURE_METADATA_HEADER),
			                         g_task_get_cancellable (azure_data->config_data->task),
			                         NULL,
			                         NULL,
			                         _get_config_fetch_done_cb_private_ipv4s,
			                         iface_data);
		}
	}

	iface_data->iface_get_config->ipv4s_len = 0;
	iface_data->iface_get_config->ipv4s_arr =
		g_new (in_addr_t , iface_data->n_ips_prefix_pending);

	{
		gs_free const char *uri = NULL;
		char buf[30];

		iface_data->n_ips_prefix_pending++;
		nm_http_client_poll_get (NM_HTTP_CLIENT (source),
		                         (uri = _azure_uri_interfaces (nm_sprintf_buf (buf, "%"G_GSSIZE_FORMAT, iface_data->iface_idx),
		                                                       "/ipv4/subnet/0/prefix/")),
		                         HTTP_TIMEOUT_MS,
		                         512*1024,
		                         10000,
		                         1000,
		                         NM_MAKE_STRV (NM_AZURE_METADATA_HEADER),
		                         g_task_get_cancellable (azure_data->config_data->task),
		                         NULL,
		                         NULL,
		                         _get_config_fetch_done_cb_subnet_cidr_prefix,
		                         iface_data);
	}
	return;

done:
	_azure_iface_data_free (iface_data);
	--azure_data->n_ifaces_pending;
	_get_config_maybe_task_return (azure_data, g_steal_pointer (&error));
}

static void
_get_config_iface_cb (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	gs_unref_bytes GBytes *response = NULL;
	AzureIfaceData *iface_data = user_data;
	gs_free_error GError *error = NULL;
	gs_free const char *uri = NULL;
	char buf[100];
	AzureData *azure_data;

	azure_data = iface_data->azure_data;

	nm_http_client_poll_get_finish (NM_HTTP_CLIENT (source),
	                                result,
	                                NULL,
	                                &response,
	                                &error);

	if (error)
		goto done;

	iface_data->hwaddr = nmcs_utils_hwaddr_normalize (g_bytes_get_data (response, NULL), -1);

	if (!iface_data->hwaddr) {
		goto done;
	}

	iface_data->iface_get_config = g_hash_table_lookup (azure_data->config_data->result_dict,
	                                                    iface_data->hwaddr);

	if (!iface_data->iface_get_config) {
		if (!iface_data->azure_data->config_data->any) {
			_LOGD ("interface[%"G_GSSIZE_FORMAT"]: ignore hwaddr %s",
			       iface_data->iface_idx,
			       iface_data->hwaddr);
			goto done;
		}
		iface_data->iface_get_config = nmcs_provider_get_config_iface_data_new (FALSE);
		g_hash_table_insert (azure_data->config_data->result_dict,
		                     g_strdup (iface_data->hwaddr),
		                     iface_data->iface_get_config);
	}

	_LOGD ("interface[%"G_GSSIZE_FORMAT"]: found a matching device with hwaddr %s",
	       iface_data->iface_idx,
	       iface_data->hwaddr);

	nm_sprintf_buf (buf, "%"G_GSSIZE_FORMAT"/ipv4/ipAddress/", iface_data->iface_idx);

	nm_http_client_poll_get (NM_HTTP_CLIENT (source),
	                         (uri = _azure_uri_interfaces (buf)),
	                         HTTP_TIMEOUT_MS,
	                         512*1024,
	                         10000,
	                         1000,
	                         NM_MAKE_STRV (NM_AZURE_METADATA_HEADER),
	                         g_task_get_cancellable (azure_data->config_data->task),
	                         NULL,
	                         NULL,
	                         _get_config_ips_prefix_list_cb,
	                         iface_data);
	return;

done:
	nm_g_slice_free (iface_data);
	--azure_data->n_ifaces_pending;
	_get_config_maybe_task_return (azure_data, g_steal_pointer (&error));
}

static void
_get_net_ifaces_list_cb (GObject *source,
                         GAsyncResult *result,
                         gpointer user_data)
{
	gs_unref_ptrarray GPtrArray *ifaces_arr = NULL;
	gs_unref_bytes GBytes *response = NULL;
	gs_free_error GError *error = NULL;
	AzureData *azure_data = user_data;
	const char *response_str;
	gsize response_len;
	const char *line;
	gsize line_len;
	guint i;

	nm_http_client_poll_get_finish (NM_HTTP_CLIENT (source),
	                                result,
	                                NULL,
	                                &response,
	                                &error);

	if (error) {
		_get_config_maybe_task_return (azure_data, g_steal_pointer (&error));
		return;
	}

	response_str = g_bytes_get_data (response, &response_len);
	/* NMHttpClient guarantees that there is a trailing NUL after the data. */
	nm_assert (response_str[response_len] == 0);

	ifaces_arr = g_ptr_array_new ();

	while (nm_utils_parse_next_line (&response_str,
	                                 &response_len,
	                                 &line,
	                                 &line_len)) {
		AzureIfaceData *iface_data;
		gssize iface_idx;

		if (line_len == 0)
			continue;

		/* Truncate the string. It's safe to do, because we own @response_data an it has an
		 * extra NULL character after the buffer. */
		((char *) line)[line_len] = '\0';

		if (line[line_len - 1] == '/' && line_len != 0)
			((char *) line)[--line_len] = '\0';

		iface_idx = _nm_utils_ascii_str_to_int64 (line, 10, 0, G_MAXSSIZE, -1);
		if (iface_idx < 0)
			continue;

		iface_data = g_slice_new (AzureIfaceData);
		*iface_data = (AzureIfaceData) {
			.iface_get_config = NULL,
			.azure_data = azure_data,
			.iface_idx = iface_idx,
			.n_ips_prefix_pending = 0,
			.hwaddr = NULL,
		};
		g_ptr_array_add (ifaces_arr, iface_data);
	}

	_LOGD ("found azure interfaces: %u", ifaces_arr->len);

	if (ifaces_arr->len == 0) {
		error = nm_utils_error_new (NM_UTILS_ERROR_UNKNOWN,
		                            "no Azure interfaces found");
		_get_config_maybe_task_return (azure_data, g_steal_pointer (&error));
		return;
	}

	for (i = 0; i < ifaces_arr->len; ++i) {
		AzureIfaceData *data = ifaces_arr->pdata[i];
		gs_free const char *uri = NULL;
		char buf[100];

		_LOGD ("azure interface[%"G_GSSIZE_FORMAT"]: retrieving configuration",
		       data->iface_idx);

		nm_sprintf_buf (buf, "%"G_GSSIZE_FORMAT"/macAddress", data->iface_idx);

		azure_data->n_ifaces_pending++;
		nm_http_client_poll_get (NM_HTTP_CLIENT (source),
		                         (uri = _azure_uri_interfaces (buf)),
		                         HTTP_TIMEOUT_MS,
		                         512*1024,
		                         10000,
		                         1000,
		                         NM_MAKE_STRV (NM_AZURE_METADATA_HEADER),
		                         g_task_get_cancellable (azure_data->config_data->task),
		                         NULL,
		                         NULL,
		                         _get_config_iface_cb,
		                         data);
	}
}

static void
get_config (NMCSProvider *provider,
            NMCSProviderGetConfigTaskData *get_config_data)
{
	gs_free const char *uri = NULL;
	AzureData *azure_data;

	azure_data = g_slice_new (AzureData);
	*azure_data = (AzureData) {
		.config_data = get_config_data,
		.n_ifaces_pending = 0,
		.success = FALSE,
	};

	nm_http_client_poll_get (nmcs_provider_get_http_client (provider),
	                         (uri = _azure_uri_interfaces ()),
	                         HTTP_TIMEOUT_MS,
	                         256 * 1024,
	                         15000,
	                         1000,
	                         NM_MAKE_STRV (NM_AZURE_METADATA_HEADER),
	                         g_task_get_cancellable (get_config_data->task),
	                         NULL,
	                         NULL,
	                         _get_net_ifaces_list_cb,
	                         azure_data);
}

/*****************************************************************************/

static void
nmcs_provider_azure_init (NMCSProviderAzure *self)
{
}

static void
nmcs_provider_azure_class_init (NMCSProviderAzureClass *klass)
{
	NMCSProviderClass *provider_class = NMCS_PROVIDER_CLASS (klass);

	provider_class->_name                 = "azure";
	provider_class->_env_provider_enabled = NMCS_ENV_VARIABLE ("NM_CLOUD_SETUP_AZURE");
	provider_class->detect                = detect;
	provider_class->get_config            = get_config;
}
