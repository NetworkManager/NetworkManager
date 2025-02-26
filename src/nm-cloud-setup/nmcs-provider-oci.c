/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "libnm-client-aux-extern/nm-default-client.h"
#include "nmcs-provider-oci.h"
#include "nm-cloud-setup-utils.h"
#include "libnm-glib-aux/nm-jansson.h"

/*****************************************************************************/

#define HTTP_TIMEOUT_MS 3000

#define NM_OCI_HEADER "Authorization:Bearer Oracle"
#define NM_OCI_HOST   "169.254.169.254"
#define NM_OCI_BASE   "http://" NM_OCI_HOST

NMCS_DEFINE_HOST_BASE(_oci_base, NMCS_ENV_NM_CLOUD_SETUP_OCI_HOST, NM_OCI_BASE);

#define _oci_uri_concat(...) nmcs_utils_uri_build_concat(_oci_base(), "opc/v2/", __VA_ARGS__)

/*****************************************************************************/

struct _NMCSProviderOCI {
    NMCSProvider parent;
};

struct _NMCSProviderOCIClass {
    NMCSProviderClass parent;
};

G_DEFINE_TYPE(NMCSProviderOCI, nmcs_provider_oci, NMCS_TYPE_PROVIDER);

/*****************************************************************************/

static void
_detect_done_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    gs_unref_object GTask *task      = user_data;
    gs_free_error GError  *get_error = NULL;
    gs_free_error GError  *error     = NULL;

    nm_http_client_poll_req_finish(NM_HTTP_CLIENT(source), result, NULL, NULL, &get_error);

    if (nm_utils_error_is_cancelled(get_error)) {
        g_task_return_error(task, g_steal_pointer(&get_error));
        return;
    }

    if (get_error) {
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "failure to get OCI instance data: %s",
                           get_error->message);
        g_task_return_error(task, g_steal_pointer(&error));
        return;
    }

    g_task_return_boolean(task, TRUE);
}

static void
detect(NMCSProvider *provider, GTask *task)
{
    NMHttpClient *http_client;
    gs_free char *uri = NULL;

    http_client = nmcs_provider_get_http_client(provider);

    nm_http_client_poll_req(http_client,
                            (uri = _oci_uri_concat("instance")),
                            HTTP_TIMEOUT_MS,
                            256 * 1024,
                            7000,
                            1000,
                            NM_MAKE_STRV(NM_OCI_HEADER),
                            NULL,
                            g_task_get_cancellable(task),
                            NULL,
                            NULL,
                            _detect_done_cb,
                            task);
}

/*****************************************************************************/

#define _VNIC_WARN(msg) _LOGW("get-config: " msg "(VNIC %s idx=%zu)", vnic_id, i)

static void
_get_config_done_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    NMCSProviderGetConfigTaskData  *get_config_data;
    NMCSProviderGetConfigIfaceData *config_iface_data;
    gs_unref_bytes GBytes          *response = NULL;
    gs_free_error GError           *error    = NULL;
    nm_auto_decref_json json_t     *vnics    = NULL;
    gboolean                        is_baremetal;
    gs_unref_ptrarray GPtrArray    *phys_nic_macs = NULL;
    GHashTableIter                  h_iter;
    size_t                          i;

    nm_http_client_poll_req_finish(NM_HTTP_CLIENT(source), result, NULL, &response, &error);

    if (nm_utils_error_is_cancelled(error))
        return;

    get_config_data = user_data;

    if (error)
        goto out;

    vnics = json_loads(g_bytes_get_data(response, NULL), JSON_REJECT_DUPLICATES, NULL);
    if (!vnics || !json_is_array(vnics)) {
        nm_utils_error_set(&error,
                           NM_UTILS_ERROR_UNKNOWN,
                           "get-config: JSON parse failure, can't configure VNICs");
        goto out;
    }

    if (json_array_size(vnics) > 0) {
        is_baremetal = NULL != json_object_get(json_array_get(vnics, 0), "nicIndex");
        _LOGI("get-config: detected %s instance", is_baremetal ? "baremetal" : "VM");
    } else {
        is_baremetal = FALSE;
        _LOGI("get-config: empty VNICs metadata, cannot detect instance type");
    }

    if (is_baremetal)
        phys_nic_macs = g_ptr_array_sized_new(16);

    for (i = 0; i < json_array_size(vnics); i++) {
        json_t       *vnic, *field;
        const char   *vnic_id = "", *val;
        gs_free char *mac     = NULL;
        in_addr_t     addr;
        int           prefix;
        json_int_t    nic_index = -1, vlan_tag = -1;

        vnic = json_array_get(vnics, i);
        if (!json_is_object(vnic)) {
            _VNIC_WARN("JSON parse failure, ignoring VNIC");
            continue;
        }

        field   = json_object_get(vnic, "vnicId");
        vnic_id = field && json_is_string(field) ? json_string_value(field) : "";

        field = json_object_get(vnic, "macAddr");
        val   = field && json_is_string(field) ? json_string_value(field) : NULL;
        mac   = val ? nmcs_utils_hwaddr_normalize(val, json_string_length(field)) : NULL;
        if (!mac) {
            _VNIC_WARN("missing or invalid 'macAddr', ignoring VNIC");
            continue;
        }

        if (is_baremetal) {
            field     = json_object_get(vnic, "nicIndex");
            nic_index = field && json_is_integer(field) ? json_integer_value(field) : -1;
            if (nic_index < 0 || nic_index >= 1024) { /* 1024 = random limit to prevent abuse*/
                _VNIC_WARN("missing or invalid 'nicIndex', ignoring VNIC");
                continue;
            }

            field    = json_object_get(vnic, "vlanTag");
            vlan_tag = field && json_is_integer(field) ? json_integer_value(field) : -1;
            if (vlan_tag < 0) {
                _VNIC_WARN("missing or invalid 'vlanTag', ignoring VNIC");
                continue;
            }
        }

        config_iface_data = nmcs_provider_get_config_iface_data_create(get_config_data, FALSE, mac);
        config_iface_data->iface_idx = i;

        field = json_object_get(vnic, "privateIp");
        val   = field && json_is_string(field) ? json_string_value(field) : NULL;
        if (val && nm_inet_parse_bin(AF_INET, val, NULL, &addr)) {
            config_iface_data->has_ipv4s    = TRUE;
            config_iface_data->ipv4s_len    = 1;
            config_iface_data->ipv4s_arr    = g_new(in_addr_t, 1);
            config_iface_data->ipv4s_arr[0] = addr;
        } else {
            _VNIC_WARN("missing or invalid 'privateIp'");
        }

        field = json_object_get(vnic, "virtualRouterIp");
        val   = field && json_is_string(field) ? json_string_value(field) : NULL;
        if (val && nm_inet_parse_bin(AF_INET, val, NULL, &addr)) {
            config_iface_data->has_gateway = TRUE;
            config_iface_data->gateway     = addr;
        } else {
            _VNIC_WARN("missing or invalid 'virtualRouterIp'");
        }

        field = json_object_get(vnic, "subnetCidrBlock");
        val   = field && json_is_string(field) ? json_string_value(field) : NULL;
        if (val && nm_inet_parse_with_prefix_bin(AF_INET, val, NULL, &addr, &prefix)) {
            config_iface_data->has_cidr    = TRUE;
            config_iface_data->cidr_addr   = addr;
            config_iface_data->cidr_prefix = prefix;
        } else {
            _VNIC_WARN("missing or invalid 'subnetCidrBlock'");
        }

        if (is_baremetal) {
            gboolean is_phys_nic = vlan_tag == 0;

            /* In baremetal instances, configure VNICs' VLAN (physical NICs don't need it) */
            if (is_phys_nic) {
                config_iface_data->priv.oci.vlan_tag      = 0;
                config_iface_data->priv.oci.parent_hwaddr = NULL;
                if (nic_index >= phys_nic_macs->len)
                    g_ptr_array_set_size(phys_nic_macs,
                                         NM_MAX((guint) (nic_index + 1), phys_nic_macs->len * 2));
                phys_nic_macs->pdata[nic_index] = (gpointer) config_iface_data->hwaddr;
            } else {
                /* We might not have all the physical NICs' MACs yet, save nicIndex for later */
                config_iface_data->priv.oci.parent_hwaddr = GINT_TO_POINTER((int) nic_index);
                config_iface_data->priv.oci.vlan_tag      = vlan_tag;
            }
        }
    }

    if (is_baremetal) {
        g_hash_table_iter_init(&h_iter, get_config_data->result_dict);

        /* Now that all the metadata is processed we should have all the physical NICs' MACs */
        while (g_hash_table_iter_next(&h_iter, NULL, (gpointer *) &config_iface_data)) {
            bool is_phys_nic = config_iface_data->priv.oci.vlan_tag == 0;
            int  nic_index   = GPOINTER_TO_INT(config_iface_data->priv.oci.parent_hwaddr);

            if (is_phys_nic)
                continue;

            if (nic_index >= phys_nic_macs->len || phys_nic_macs->pdata[nic_index] == NULL) {
                _LOGW("get-config: physical NIC for nicIndex=%d not found, ignoring VNIC "
                      "(VNIC macAddr=%s)",
                      nic_index,
                      config_iface_data->hwaddr);
                g_hash_table_iter_remove(&h_iter);
                continue;
            }

            config_iface_data->priv.oci.parent_hwaddr = g_strdup(phys_nic_macs->pdata[nic_index]);
        }
    }

out:
    _nmcs_provider_get_config_task_maybe_return(get_config_data, g_steal_pointer(&error));
}

static void
get_config(NMCSProvider *provider, NMCSProviderGetConfigTaskData *get_config_data)
{
    gs_free const char *uri = NULL;

    nm_http_client_poll_req(nmcs_provider_get_http_client(provider),
                            (uri = _oci_uri_concat("vnics")),
                            HTTP_TIMEOUT_MS,
                            256 * 1024,
                            15000,
                            1000,
                            NM_MAKE_STRV(NM_OCI_HEADER),
                            NULL,
                            get_config_data->intern_cancellable,
                            NULL,
                            NULL,
                            _get_config_done_cb,
                            get_config_data);
}

/*****************************************************************************/

static void
nmcs_provider_oci_init(NMCSProviderOCI *self)
{}

static void
dispose(GObject *object)
{
    G_OBJECT_CLASS(nmcs_provider_oci_parent_class)->dispose(object);
}

static void
nmcs_provider_oci_class_init(NMCSProviderOCIClass *klass)
{
    GObjectClass      *object_class   = G_OBJECT_CLASS(klass);
    NMCSProviderClass *provider_class = NMCS_PROVIDER_CLASS(klass);

    object_class->dispose = dispose;

    provider_class->_name                 = "oci";
    provider_class->_env_provider_enabled = NMCS_ENV_NM_CLOUD_SETUP_OCI;
    provider_class->detect                = detect;
    provider_class->get_config            = get_config;
}
