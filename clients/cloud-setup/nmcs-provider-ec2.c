// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nmcs-provider-ec2.h"

#include "nm-cloud-setup-utils.h"

/*****************************************************************************/

#define HTTP_TIMEOUT_MS 3000

#define NM_EC2_HOST               "169.254.169.254"
#define NM_EC2_BASE               "http://" NM_EC2_HOST
#define NM_EC2_API_VERSION        "2018-09-24"
#define NM_EC2_METADATA_URL_BASE  /* $NM_EC2_BASE/$NM_EC2_API_VERSION */ "/meta-data/network/interfaces/macs/"

static const char *
_ec2_base (void)
{
	static const char *base_cached = NULL;
	const char *base;

again:
	base = g_atomic_pointer_get (&base_cached);
	if (G_UNLIKELY (!base)) {
		/* The base URI can be set via environment variable.
		 * This is only for testing, not really to be configurable! */
		base = g_getenv ("NM_CLOUD_SETUP_EC2_HOST");
		if (   base
		    && base[0]
		    && !strchr (base, '/')) {
			if (   NM_STR_HAS_PREFIX (base, "http://")
			    || NM_STR_HAS_PREFIX (base, "https://"))
				base = g_intern_string (base);
			else {
				gs_free char *s = NULL;

				s = g_strconcat ("http://", base, NULL);
				base = g_intern_string (s);
			}
		}
		if (!base)
			base = NM_EC2_BASE;

		nm_assert (!NM_STR_HAS_SUFFIX (base, "/"));

		if (!g_atomic_pointer_compare_and_exchange (&base_cached, NULL, base))
			goto again;
	}

	return base;
}

#define _ec2_uri_concat(...)     nmcs_utils_uri_build_concat (_ec2_base (), __VA_ARGS__)
#define _ec2_uri_interfaces(...) _ec2_uri_concat (NM_EC2_API_VERSION, NM_EC2_METADATA_URL_BASE, ##__VA_ARGS__)

/*****************************************************************************/

struct _NMCSProviderEC2 {
	NMCSProvider parent;
};

struct _NMCSProviderEC2Class {
	NMCSProviderClass parent;
};

G_DEFINE_TYPE (NMCSProviderEC2, nmcs_provider_ec2, NMCS_TYPE_PROVIDER);

/*****************************************************************************/

static gboolean
_detect_get_meta_data_check_cb (long response_code,
                                GBytes *response_data,
                                gpointer check_user_data,
                                GError **error)
{
	return    response_code == 200
	       && nmcs_utils_parse_get_full_line (response_data, "ami-id");
}

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

	if (nm_utils_error_is_cancelled (get_error, FALSE)) {
		g_task_return_error (task, g_steal_pointer (&get_error));
		return;
	}

	if (get_error) {
		nm_utils_error_set (&error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "failure to get EC2 metadata: %s",
		                    get_error->message);
		g_task_return_error (task, g_steal_pointer (&error));
		return;
	}

	if (!success) {
		nm_utils_error_set (&error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "failure to detect EC2 metadata");
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
	                         (uri = _ec2_uri_concat ("latest/meta-data/")),
	                         HTTP_TIMEOUT_MS,
	                         256*1024,
	                         7000,
	                         1000,
	                         g_task_get_cancellable (task),
	                         _detect_get_meta_data_check_cb,
	                         NULL,
	                         _detect_get_meta_data_done_cb,
	                         task);
}

/*****************************************************************************/

typedef struct {
	NMCSProviderGetConfigTaskData *get_config_data;
	GCancellable *cancellable;
	gulong cancelled_id;
	guint n_pending;
} GetConfigIfaceData;

static void
_get_config_task_return (GetConfigIfaceData *iface_data,
                         GError *error_take)
{
	NMCSProviderGetConfigTaskData *get_config_data = iface_data->get_config_data;

	nm_clear_g_cancellable_disconnect (g_task_get_cancellable (get_config_data->task),
	                                   &iface_data->cancelled_id);

	nm_clear_g_cancellable (&iface_data->cancellable);

	nm_g_slice_free (iface_data);

	if (error_take) {
		if (nm_utils_error_is_cancelled (error_take, FALSE))
			_LOGD ("get-config: cancelled");
		else
			_LOGD ("get-config: failed: %s", error_take->message);
		g_task_return_error (get_config_data->task, error_take);
	} else {
		_LOGD ("get-config: success");
		g_task_return_pointer (get_config_data->task,
		                       g_hash_table_ref (get_config_data->result_dict),
		                       (GDestroyNotify) g_hash_table_unref);
	}

	g_object_unref (get_config_data->task);
}

static void
_get_config_fetch_done_cb (NMHttpClient *http_client,
                           GAsyncResult *result,
                           gpointer user_data,
                           gboolean is_local_ipv4)
{
	GetConfigIfaceData *iface_data;
	NMCSProviderGetConfigTaskData *get_config_data;
	const char *hwaddr = NULL;
	gs_unref_bytes GBytes *response_data = NULL;
	gs_free_error GError *error = NULL;
	gboolean success;
	NMCSProviderGetConfigIfaceData *config_iface_data;

	nm_utils_user_data_unpack (user_data, &iface_data, &hwaddr);

	success = nm_http_client_poll_get_finish (http_client,
	                                          result,
	                                          NULL,
	                                          &response_data,
	                                          &error);
	if (nm_utils_error_is_cancelled (error, FALSE))
		return;

	get_config_data = iface_data->get_config_data;

	config_iface_data = g_hash_table_lookup (get_config_data->result_dict, hwaddr);

	if (success) {
		in_addr_t tmp_addr;
		int tmp_prefix;

		if (is_local_ipv4) {
			gs_free const char **s_addrs = NULL;
			gsize i, len;

			s_addrs = nm_utils_strsplit_set_full (g_bytes_get_data (response_data, NULL), "\n", NM_UTILS_STRSPLIT_SET_FLAGS_STRSTRIP);
			len = NM_PTRARRAY_LEN (s_addrs);

			nm_assert (!config_iface_data->has_ipv4s);
			nm_assert (!config_iface_data->ipv4s_arr);
			config_iface_data->has_ipv4s = TRUE;
			config_iface_data->ipv4s_len = 0;
			if (len > 0) {
				config_iface_data->ipv4s_arr = g_new (in_addr_t, len);

				for (i = 0; i < len; i++) {
					if (nm_utils_parse_inaddr_bin (AF_INET,
					                               s_addrs[i],
					                               NULL,
					                               &tmp_addr))
						config_iface_data->ipv4s_arr[config_iface_data->ipv4s_len++] = tmp_addr;
				}
			}
		} else {
			if (nm_utils_parse_inaddr_prefix_bin (AF_INET,
			                                      g_bytes_get_data (response_data, NULL),
			                                      NULL,
			                                      &tmp_addr,
			                                      &tmp_prefix)) {
				nm_assert (!config_iface_data->has_cidr);
				config_iface_data->has_cidr = TRUE;
				config_iface_data->cidr_prefix = tmp_prefix;
				config_iface_data->cidr_addr = tmp_addr;
			}
		}
	}

	if (--iface_data->n_pending > 0)
		return;

	_get_config_task_return (iface_data, NULL);
}

static void
_get_config_fetch_done_cb_subnet_ipv4_cidr_block (GObject *source,
                                                  GAsyncResult *result,
                                                  gpointer user_data)
{
	_get_config_fetch_done_cb (NM_HTTP_CLIENT (source), result, user_data, FALSE);
}

static void
_get_config_fetch_done_cb_local_ipv4s (GObject *source,
                                       GAsyncResult *result,
                                       gpointer user_data)
{
	_get_config_fetch_done_cb (NM_HTTP_CLIENT (source), result, user_data, TRUE);
}

static void
_get_config_fetch_cancelled_cb (GObject *object, gpointer user_data)
{
	GetConfigIfaceData *iface_data = user_data;

	if (iface_data->cancelled_id == 0)
		return;

	nm_clear_g_signal_handler (g_task_get_cancellable (iface_data->get_config_data->task),
	                           &iface_data->cancelled_id);
	_get_config_task_return (iface_data,
	                         nm_utils_error_new_cancelled (FALSE, NULL));
}

typedef struct {
	NMCSProviderGetConfigTaskData *get_config_data;
	GHashTable *response_parsed;
} GetConfigMetadataData;

typedef struct {
	gssize iface_idx;
	char path[0];
} GetConfigMetadataMac;

static void
_get_config_metadata_ready_cb (GObject *source,
                               GAsyncResult *result,
                               gpointer user_data)
{
	GetConfigMetadataData *metadata_data = user_data;
	GetConfigIfaceData *iface_data;
	NMCSProviderGetConfigTaskData *get_config_data = metadata_data->get_config_data;
	gs_unref_hashtable GHashTable *response_parsed = g_steal_pointer (&metadata_data->response_parsed);
	gs_free_error GError *error = NULL;
	GCancellable *cancellable;
	GetConfigMetadataMac *v_mac_data;
	const char *v_hwaddr;
	GHashTableIter h_iter;
	NMHttpClient *http_client;

	nm_g_slice_free (metadata_data);

	nm_http_client_poll_get_finish (NM_HTTP_CLIENT (source),
	                                result,
	                                NULL,
	                                NULL,
	                                &error);

	iface_data = g_slice_new (GetConfigIfaceData);
	*iface_data = (GetConfigIfaceData) {
		.get_config_data = get_config_data,
		.n_pending       = 0,
	};

	if (nm_utils_error_is_cancelled (error, FALSE)) {
		_get_config_task_return (iface_data, g_steal_pointer (&error));
		return;
	}

	/* We ignore errors. Only if we got no response at all, it's a problem.
	 * Otherwise, we proceed with whatever we could fetch. */
	if (!response_parsed) {
		_get_config_task_return (iface_data,
		                         nm_utils_error_new (NM_UTILS_ERROR_UNKNOWN,
		                                             "meta data for interfaces not found"));
		return;
	}

	cancellable = g_task_get_cancellable (get_config_data->task);
	if (cancellable) {
		gulong cancelled_id;

		cancelled_id = g_cancellable_connect (cancellable,
		                                      G_CALLBACK (_get_config_fetch_cancelled_cb),
		                                      iface_data,
		                                      NULL);
		if (cancelled_id == 0) {
			_get_config_task_return (iface_data,
			                         nm_utils_error_new_cancelled (FALSE, NULL));
			return;
		}

		iface_data->cancelled_id = cancelled_id;
	}

	iface_data->cancellable = g_cancellable_new ();

	http_client = nmcs_provider_get_http_client (g_task_get_source_object (get_config_data->task));

	g_hash_table_iter_init (&h_iter, response_parsed);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &v_hwaddr, (gpointer *) &v_mac_data)) {
		NMCSProviderGetConfigIfaceData *config_iface_data;
		gs_free char *uri1 = NULL;
		gs_free char *uri2 = NULL;
		const char *hwaddr;

		if (!g_hash_table_lookup_extended (get_config_data->result_dict, v_hwaddr, (gpointer *) &hwaddr, (gpointer *) &config_iface_data)) {
			if (!get_config_data->any) {
				_LOGD ("get-config: skip fetching meta data for %s (%s)", v_hwaddr, v_mac_data->path);
				continue;
			}
			config_iface_data = nmcs_provider_get_config_iface_data_new (FALSE);
			g_hash_table_insert (get_config_data->result_dict,
			                     (char *) (hwaddr = g_strdup (v_hwaddr)),
			                     config_iface_data);
		}

		nm_assert (config_iface_data->iface_idx == -1);
		config_iface_data->iface_idx = v_mac_data->iface_idx;

		_LOGD ("get-config: start fetching meta data for #%"G_GSSIZE_FORMAT", %s (%s)", config_iface_data->iface_idx, hwaddr, v_mac_data->path);

		iface_data->n_pending++;
		nm_http_client_poll_get (http_client,
		                         (uri1 = _ec2_uri_interfaces (v_mac_data->path,
		                                                        NM_STR_HAS_SUFFIX (v_mac_data->path, "/")
		                                                      ? ""
		                                                      : "/",
		                                                      "subnet-ipv4-cidr-block")),
		                         HTTP_TIMEOUT_MS,
		                         512*1024,
		                         10000,
		                         1000,
		                         iface_data->cancellable,
		                         NULL,
		                         NULL,
		                         _get_config_fetch_done_cb_subnet_ipv4_cidr_block,
		                         nm_utils_user_data_pack (iface_data, hwaddr));

		iface_data->n_pending++;
		nm_http_client_poll_get (http_client,
		                         (uri2 = _ec2_uri_interfaces (v_mac_data->path,
		                                                        NM_STR_HAS_SUFFIX (v_mac_data->path, "/")
		                                                      ? ""
		                                                      : "/",
		                                                      "local-ipv4s")),
		                         HTTP_TIMEOUT_MS,
		                         512*1024,
		                         10000,
		                         1000,
		                         iface_data->cancellable,
		                         NULL,
		                         NULL,
		                         _get_config_fetch_done_cb_local_ipv4s,
		                         nm_utils_user_data_pack (iface_data, hwaddr));
	}

	if (iface_data->n_pending == 0)
		_get_config_task_return (iface_data, NULL);
}

static gboolean
_get_config_metadata_ready_check (long response_code,
                                  GBytes *response_data,
                                  gpointer check_user_data,
                                  GError **error)
{
	GetConfigMetadataData *metadata_data = check_user_data;
	gs_unref_hashtable GHashTable *response_parsed = NULL;
	const guint8 *r_data;
	gsize r_len;
	GHashTableIter h_iter;
	gboolean has_all;
	const char *c_hwaddr;
	gssize iface_idx_counter = 0;

	if (   response_code != 200
	    || !response_data) {
		/* we wait longer. */
		return FALSE;
	}

	r_data = g_bytes_get_data (response_data, &r_len);

	while (r_len > 0) {
		const guint8 *p_eol;
		const char *p_start;
		gsize p_start_l;
		gsize p_start_l_2;
		char *hwaddr;
		GetConfigMetadataMac *mac_data;

		p_start = (const char *) r_data;

		p_eol = memchr (r_data, '\n', r_len);
		if (p_eol) {
			p_start_l = (p_eol - r_data);
			r_len -= p_start_l + 1;
			r_data = &p_eol[1];
		} else {
			p_start_l = r_len;
			r_data = &r_data[r_len];
			r_len = 0;
		}

		if (p_start_l == 0)
			continue;

		p_start_l_2 = p_start_l;
		if (p_start[p_start_l_2 - 1] == '/') {
			/* trim the trailing "/". */
			p_start_l_2--;
		}

		hwaddr = nmcs_utils_hwaddr_normalize (p_start, p_start_l_2);
		if (!hwaddr)
			continue;

		if (!response_parsed)
			response_parsed = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);

		mac_data = g_malloc (sizeof (GetConfigMetadataData) + 1 + p_start_l);
		mac_data->iface_idx = iface_idx_counter++;
		memcpy (mac_data->path, p_start, p_start_l);
		mac_data->path[p_start_l] = '\0';

		g_hash_table_insert (response_parsed, hwaddr, mac_data);
	}

	has_all = TRUE;
	g_hash_table_iter_init (&h_iter, metadata_data->get_config_data->result_dict);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &c_hwaddr, NULL)) {
		if (   !response_parsed
		    || !g_hash_table_contains (response_parsed, c_hwaddr)) {
			has_all = FALSE;
			break;
		}
	}

	nm_clear_pointer (&metadata_data->response_parsed, g_hash_table_unref);
	metadata_data->response_parsed = g_steal_pointer (&response_parsed);
	return has_all;
}

static void
get_config (NMCSProvider *provider,
            NMCSProviderGetConfigTaskData *get_config_data)
{
	gs_free char *uri = NULL;
	GetConfigMetadataData *metadata_data;

	metadata_data = g_slice_new (GetConfigMetadataData);
	*metadata_data = (GetConfigMetadataData) {
		.get_config_data = get_config_data,
	};

	/* First we fetch the "macs/". If the caller requested some particular
	 * MAC addresses, then we poll until we see them. They might not yet be
	 * around from the start...
	 */
	nm_http_client_poll_get (nmcs_provider_get_http_client (provider),
	                         (uri = _ec2_uri_interfaces ()),
	                         HTTP_TIMEOUT_MS,
	                         256 * 1024,
	                         15000,
	                         1000,
	                         g_task_get_cancellable (get_config_data->task),
	                         _get_config_metadata_ready_check,
	                         metadata_data,
	                         _get_config_metadata_ready_cb,
	                         metadata_data);
}

/*****************************************************************************/

static void
nmcs_provider_ec2_init (NMCSProviderEC2 *self)
{
}

static void
nmcs_provider_ec2_class_init (NMCSProviderEC2Class *klass)
{
	NMCSProviderClass *provider_class = NMCS_PROVIDER_CLASS (klass);

	provider_class->_name                 = "ec2";
	provider_class->_env_provider_enabled = "NM_CLOUD_SETUP_EC2";
	provider_class->detect                = detect;
	provider_class->get_config            = get_config;
}
