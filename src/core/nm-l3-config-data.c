/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "src/core/nm-default-daemon.h"

#include "nm-l3-config-data.h"

#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>

#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-glib-aux/nm-enum-utils.h"
#include "libnm-glib-aux/nm-ref-string.h"
#include "libnm-platform/nm-platform-utils.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-object.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

typedef struct {
    NMDedupMultiIdxType parent;
    NMPObjectType       obj_type;
} DedupMultiIdxType;

struct _NML3ConfigData {
    NMDedupMultiIndex *multi_idx;

    union {
        struct {
            DedupMultiIdxType idx_addresses_6;
            DedupMultiIdxType idx_addresses_4;
        };
        DedupMultiIdxType idx_addresses_x[2];
    };

    union {
        struct {
            DedupMultiIdxType idx_routes_6;
            DedupMultiIdxType idx_routes_4;
        };
        DedupMultiIdxType idx_routes_x[2];
    };

    union {
        struct {
            const NMPObject *best_default_route_6;
            const NMPObject *best_default_route_4;
        };
        const NMPObject *best_default_route_x[2];
    };

    GArray *wins;
    GArray *nis_servers;

    NMRefString *nis_domain;
    NMRefString *proxy_pac_url;
    NMRefString *proxy_pac_script;

    union {
        struct {
            NMDhcpLease *dhcp_lease_6;
            NMDhcpLease *dhcp_lease_4;
        };
        NMDhcpLease *dhcp_lease_x[2];
    };

    union {
        struct {
            GArray *nameservers_6;
            GArray *nameservers_4;
        };
        GArray *nameservers_x[2];
    };

    union {
        struct {
            GPtrArray *domains_6;
            GPtrArray *domains_4;
        };
        GPtrArray *domains_x[2];
    };

    union {
        struct {
            GPtrArray *searches_6;
            GPtrArray *searches_4;
        };
        GPtrArray *searches_x[2];
    };

    union {
        struct {
            GPtrArray *dns_options_6;
            GPtrArray *dns_options_4;
        };
        GPtrArray *dns_options_x[2];
    };

    int ifindex;

    int ref_count;

    union {
        struct {
            int dns_priority_6;
            int dns_priority_4;
        };
        int dns_priority_x[2];
    };

    union {
        struct {
            NMIPRouteTableSyncMode route_table_sync_6;
            NMIPRouteTableSyncMode route_table_sync_4;
        };
        NMIPRouteTableSyncMode route_table_sync_x[2];
    };

    NMSettingConnectionMdns       mdns;
    NMSettingConnectionLlmnr      llmnr;
    NMSettingConnectionDnsOverTls dns_over_tls;
    NMUtilsIPv6IfaceId            ip6_token;

    NML3ConfigDatFlags flags;

    NMIPConfigSource source;

    int ndisc_hop_limit_val;

    guint32 mtu;
    guint32 ip6_mtu;
    guint32 ndisc_reachable_time_msec_val;
    guint32 ndisc_retrans_timer_msec_val;

    union {
        struct {
            NMOptionBool never_default_6;
            NMOptionBool never_default_4;
        };
        NMOptionBool never_default_x[2];
    };

    NMTernary metered : 3;

    NMTernary proxy_browser_only : 3;

    NMProxyConfigMethod proxy_method : 4;

    NMSettingIP6ConfigPrivacy ip6_privacy : 4;

    bool is_sealed : 1;

    bool has_routes_with_type_local_4_set : 1;
    bool has_routes_with_type_local_6_set : 1;
    bool has_routes_with_type_local_4_val : 1;
    bool has_routes_with_type_local_6_val : 1;

    bool ndisc_hop_limit_set : 1;
    bool ndisc_reachable_time_msec_set : 1;
    bool ndisc_retrans_timer_msec_set : 1;
};

/*****************************************************************************/

static GArray *
_garray_inaddr_ensure(GArray **p_arr, int addr_family)
{
    nm_assert(p_arr);
    nm_assert_addr_family(addr_family);

    if (G_UNLIKELY(!*p_arr)) {
        *p_arr = g_array_new(FALSE, FALSE, nm_utils_addr_family_to_size(addr_family));
    }
    return *p_arr;
}

static GArray *
_garray_inaddr_clone(const GArray *src, int addr_family)
{
    const gsize elt_size = nm_utils_addr_family_to_size(addr_family);
    GArray     *dst;

    nm_assert_addr_family(addr_family);

    if (!src || src->len == 0)
        return NULL;

    dst = g_array_sized_new(FALSE, FALSE, elt_size, src->len);
    g_array_set_size(dst, src->len);
    memcpy(dst->data, src->data, src->len * elt_size);
    return dst;
}

static void
_garray_inaddr_merge(GArray **p_dst, const GArray *src, int addr_family)
{
    guint       dst_initial_len;
    const char *p_dst_arr;
    const char *p_src;
    gsize       elt_size;
    guint       i;
    guint       j;

    if (nm_g_array_len(src) == 0)
        return;

    if (!*p_dst) {
        *p_dst = _garray_inaddr_clone(src, addr_family);
        return;
    }

    elt_size = nm_utils_addr_family_to_size(addr_family);

    dst_initial_len = (*p_dst)->len;
    p_dst_arr       = (*p_dst)->data;
    p_src           = src->data;

    for (i = 0; i < src->len; i++, p_src += elt_size) {
        for (j = 0; j < dst_initial_len; j++) {
            if (memcmp(&p_dst_arr[j * elt_size], p_src, elt_size) == 0)
                goto next;
        }
        g_array_append_vals(*p_dst, p_src, 1);
        p_dst_arr = (*p_dst)->data;
next:;
    }
}

static gssize
_garray_inaddr_find(GArray                            *arr,
                    int                                addr_family,
                    gconstpointer                      needle,
                    /* (const NMIPAddr **) */ gpointer out_addr)
{
    guint i;

    nm_assert_addr_family(addr_family);
    nm_assert(needle);

    if (arr) {
        const gsize elt_size = nm_utils_addr_family_to_size(addr_family);
        const char *p;

        p = arr->data;
        for (i = 0; i < arr->len; i++, p += elt_size) {
            if (memcmp(p, needle, elt_size) == 0) {
                NM_SET_OUT((gconstpointer *) out_addr, p);
                return i;
            }
        }
    }
    NM_SET_OUT((gconstpointer *) out_addr, NULL);
    return -1;
}

static gconstpointer
_garray_inaddr_get(GArray *arr, guint *out_len)
{
    nm_assert(out_len);

    if (!arr) {
        *out_len = 0;
        return NULL;
    }
    *out_len = arr->len;
    return arr->data;
}

static gconstpointer
_garray_inaddr_at(GArray *arr, gboolean IS_IPv4, guint idx)
{
    nm_assert(arr);
    nm_assert(idx < arr->len);

    if (IS_IPv4)
        return &g_array_index(arr, in_addr_t, idx);
    return &g_array_index(arr, struct in6_addr, idx);
}

static gboolean
_garray_inaddr_add(GArray **p_arr, int addr_family, gconstpointer addr)
{
    nm_assert(p_arr);
    nm_assert_addr_family(addr_family);
    nm_assert(addr);

    if (!*p_arr)
        _garray_inaddr_ensure(p_arr, addr_family);
    else {
        if (_garray_inaddr_find(*p_arr, addr_family, addr, NULL) >= 0)
            return FALSE;
    }

    g_array_append_vals(*p_arr, addr, 1);
    return TRUE;
}

static int
_garray_inaddr_cmp(const GArray *a, const GArray *b, int addr_family)
{
    guint l;

    l = nm_g_array_len(a);
    NM_CMP_DIRECT(l, nm_g_array_len(b));

    if (l > 0)
        NM_CMP_DIRECT_MEMCMP(a->data, b->data, l * nm_utils_addr_family_to_size(addr_family));

    return 0;
}

static void
_strv_ptrarray_merge(GPtrArray **p_dst, const GPtrArray *src)
{
    guint dst_initial_len;
    guint i;

    if (nm_g_ptr_array_len(src) == 0)
        return;

    if (!*p_dst) {
        /* we trust src to contain unique strings. Just clone it. */
        *p_dst = nm_strv_ptrarray_clone(src, TRUE);
        return;
    }

    nm_strv_ptrarray_ensure(p_dst);

    dst_initial_len = (*p_dst)->len;

    for (i = 0; i < src->len; i++) {
        const char *s = src->pdata[i];

        if (dst_initial_len > 0
            && nm_strv_find_first((const char *const *) ((*p_dst)->pdata), dst_initial_len, s) >= 0)
            continue;

        g_ptr_array_add(*p_dst, g_strdup(s));
    }
}

/*****************************************************************************/

void
nm_l3_config_data_log(const NML3ConfigData *self,
                      const char           *title,
                      const char           *prefix,
                      NMLogLevel            log_level,
                      NMLogDomain           log_domain)
{
    char  sbuf[sizeof(_nm_utils_to_string_buffer)];
    char  sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];
    int   IS_IPv4;
    guint i;

    if (!nm_logging_enabled(log_level, log_domain))
        return;

#define _L(...)                                      \
    _nm_log(log_level,                               \
            log_domain,                              \
            0,                                       \
            NULL,                                    \
            NULL,                                    \
            "%s" _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
            prefix _NM_UTILS_MACRO_REST(__VA_ARGS__))

    if (!prefix)
        prefix = "";

    if (!self) {
        _L("l3cd %s%s%s(NULL)", NM_PRINT_FMT_QUOTED(title, "\"", title, "\" ", ""));
        return;
    }

    nm_assert(!NM_FLAGS_ANY(self->flags,
                            ~(NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES
                              | NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_4
                              | NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_6)));

    _L("l3cd %s%s%s(" NM_HASH_OBFUSCATE_PTR_FMT ", ifindex=%d%s%s%s%s)",
       NM_PRINT_FMT_QUOTED(title, "\"", title, "\" ", ""),
       NM_HASH_OBFUSCATE_PTR(self),
       self->ifindex,
       NM_PRINT_FMT_QUOTED2(self->source != NM_IP_CONFIG_SOURCE_UNKNOWN,
                            ", source=",
                            nmp_utils_ip_config_source_to_string(self->source, sbuf, sizeof(sbuf)),
                            ""),
       NM_FLAGS_HAS(self->flags, NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES)
           ? ", merge-no-default-routes"
           : "",
       !self->is_sealed ? ", not-sealed" : "");

    if (self->mtu != 0 || self->ip6_mtu != 0) {
        _L("mtu: %u, ip6-mtu: %u", self->mtu, self->ip6_mtu);
    }

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        const int        addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        NMDedupMultiIter iter;
        const NMPObject *obj;

        i = 0;
        nm_l3_config_data_iter_obj_for_each (&iter,
                                             self,
                                             &obj,
                                             NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4)) {
            _L("address%c[%u]: %s",
               nm_utils_addr_family_to_char(addr_family),
               i,
               nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            i++;
        }

        if (!IS_IPv4) {
            if (self->ip6_privacy != NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN) {
                gs_free char *s = NULL;

                _L("ip6-privacy: %s",
                   (s = _nm_utils_enum_to_str_full(nm_setting_ip6_config_privacy_get_type(),
                                                   self->ip6_privacy,
                                                   " ",
                                                   NULL)));
            }
        }

        i = 0;
        nm_l3_config_data_iter_obj_for_each (&iter, self, &obj, NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
            _L("route%c[%u]: %s%s",
               nm_utils_addr_family_to_char(addr_family),
               i,
               self->best_default_route_x[IS_IPv4] == obj ? "[DEFAULT] " : "",
               nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            i++;
        }

        if (self->route_table_sync_x[IS_IPv4] != NM_IP_ROUTE_TABLE_SYNC_MODE_NONE) {
            _L("route-table-sync-mode%c: %d",
               nm_utils_addr_family_to_char(addr_family),
               (int) self->route_table_sync_x[IS_IPv4]);
        }

        if (!IS_IPv4) {
            if (self->ndisc_hop_limit_set || self->ndisc_reachable_time_msec_set
                || self->ndisc_retrans_timer_msec_set) {
                gsize       l        = sizeof(sbuf);
                char       *p        = sbuf;
                const char *s_prefix = "ndisc: ";

                if (self->ndisc_hop_limit_set) {
                    nm_strbuf_append(&p, &l, "%shop-limit=%d", s_prefix, self->ndisc_hop_limit_val);
                    s_prefix = ", ";
                }
                if (self->ndisc_reachable_time_msec_set) {
                    nm_strbuf_append(&p,
                                     &l,
                                     "%sreachable-time-msec=%u",
                                     s_prefix,
                                     self->ndisc_reachable_time_msec_val);
                    s_prefix = ", ";
                }
                if (self->ndisc_retrans_timer_msec_set) {
                    nm_strbuf_append(&p,
                                     &l,
                                     "%sretrans-timer-msec=%u",
                                     s_prefix,
                                     self->ndisc_retrans_timer_msec_val);
                    s_prefix = ", ";
                }
                _L("%s", sbuf);
            }
        }

        if (NM_FLAGS_ANY(self->flags, NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY(IS_IPv4))) {
            _L("dns-priority%c: %d",
               nm_utils_addr_family_to_char(addr_family),
               self->dns_priority_x[IS_IPv4]);
        }

        for (i = 0; i < nm_g_array_len(self->nameservers_x[IS_IPv4]); i++) {
            _L("nameserver%c[%u]: %s",
               nm_utils_addr_family_to_char(addr_family),
               i,
               nm_utils_inet_ntop(addr_family,
                                  _garray_inaddr_at(self->nameservers_x[IS_IPv4], IS_IPv4, i),
                                  sbuf_addr));
        }

        for (i = 0; i < nm_g_ptr_array_len(self->domains_x[IS_IPv4]); i++) {
            _L("domain%c[%u]: %s",
               nm_utils_addr_family_to_char(addr_family),
               i,
               (const char *) self->domains_x[IS_IPv4]->pdata[i]);
        }

        for (i = 0; i < nm_g_ptr_array_len(self->searches_x[IS_IPv4]); i++) {
            _L("search%c[%u]: %s",
               nm_utils_addr_family_to_char(addr_family),
               i,
               (const char *) self->searches_x[IS_IPv4]->pdata[i]);
        }

        for (i = 0; i < nm_g_ptr_array_len(self->dns_options_x[IS_IPv4]); i++) {
            _L("dns_option%c[%u]: %s",
               nm_utils_addr_family_to_char(addr_family),
               i,
               (const char *) self->dns_options_x[IS_IPv4]->pdata[i]);
        }

        if (IS_IPv4) {
            for (i = 0; i < nm_g_array_len(self->wins); i++) {
                _L("wins[%u]: %s",
                   i,
                   _nm_utils_inet4_ntop(g_array_index(self->wins, in_addr_t, i), sbuf_addr));
            }
            for (i = 0; i < nm_g_array_len(self->nis_servers); i++) {
                _L("nis-server[%u]: %s",
                   i,
                   _nm_utils_inet4_ntop(g_array_index(self->nis_servers, in_addr_t, i), sbuf_addr));
            }
            if (self->nis_domain)
                _L("nis-domain: %s", self->nis_domain->str);
        }

        if (self->dhcp_lease_x[IS_IPv4]) {
            gs_free NMUtilsNamedValue *options_free = NULL;
            NMUtilsNamedValue          options_buffer[30];
            NMUtilsNamedValue         *options;
            guint                      options_len;

            options = nm_utils_named_values_from_strdict(
                nm_dhcp_lease_get_options(self->dhcp_lease_x[IS_IPv4]),
                &options_len,
                options_buffer,
                &options_free);
            if (options_len == 0) {
                _L("dhcp-lease%c (%u options)",
                   nm_utils_addr_family_to_char(addr_family),
                   options_len);
            }
            for (i = 0; i < options_len; i++) {
                _L("dhcp-lease%c[%u]: \"%s\" => \"%s\"",
                   nm_utils_addr_family_to_char(addr_family),
                   i,
                   options[i].name,
                   options[i].value_str);
            }
        }

        if (self->never_default_x[IS_IPv4] != NM_OPTION_BOOL_DEFAULT)
            _L("never-default: %s", self->never_default_x[IS_IPv4] ? "yes" : "no");
    }

    if (self->mdns != NM_SETTING_CONNECTION_MDNS_DEFAULT) {
        gs_free char *s = NULL;

        _L("mdns: %s",
           (s = _nm_utils_enum_to_str_full(nm_setting_connection_mdns_get_type(),
                                           self->mdns,
                                           " ",
                                           NULL)));
    }

    if (self->llmnr != NM_SETTING_CONNECTION_LLMNR_DEFAULT) {
        gs_free char *s = NULL;

        _L("llmnr: %s",
           (s = _nm_utils_enum_to_str_full(nm_setting_connection_llmnr_get_type(),
                                           self->llmnr,
                                           " ",
                                           NULL)));
    }

    if (self->dns_over_tls != NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT) {
        gs_free char *s = NULL;

        _L("dns-over-tls: %s",
           (s = _nm_utils_enum_to_str_full(nm_setting_connection_dns_over_tls_get_type(),
                                           self->dns_over_tls,
                                           " ",
                                           NULL)));
    }

    if (self->ip6_token.id != 0) {
        _L("ipv6-token: %s",
           nm_utils_inet6_interface_identifier_to_token(&self->ip6_token, sbuf_addr));
    }

    if (self->metered != NM_TERNARY_DEFAULT)
        _L("metered: %s", self->metered ? "yes" : "no");

    if (self->proxy_browser_only != NM_TERNARY_DEFAULT)
        _L("proxy-browser-only: %s", self->proxy_browser_only ? "yes" : "no");

    if (self->proxy_method != NM_PROXY_CONFIG_METHOD_UNKNOWN)
        _L("proxy-method: %s", self->proxy_method == NM_PROXY_CONFIG_METHOD_AUTO ? "auto" : "none");

    if (self->proxy_pac_url)
        _L("proxy-pac-url: %s", self->proxy_pac_url->str);

    if (self->proxy_pac_script)
        _L("proxy-pac-script: %s", self->proxy_pac_script->str);
#undef _L
}

/*****************************************************************************/

static gboolean
_route_valid_4(const NMPlatformIP4Route *r)
{
    return r && r->plen <= 32
           && r->network == nm_utils_ip4_address_clear_host_address(r->network, r->plen);
}

static gboolean
_route_valid_6(const NMPlatformIP6Route *r)
{
    struct in6_addr n;

    return r && r->plen <= 128
           && (memcmp(&r->network,
                      nm_utils_ip6_address_clear_host_address(&n, &r->network, r->plen),
                      sizeof(n))
               == 0);
}

static gboolean
_route_valid(int addr_family, gconstpointer r)
{
    return NM_IS_IPv4(addr_family) ? _route_valid_4(r) : _route_valid_6(r);
}

static gboolean
_NM_IS_L3_CONFIG_DATA(const NML3ConfigData *self, gboolean allow_sealed)
{
    nm_assert(!self || (self->ifindex >= 0 && self->multi_idx && self->ref_count > 0));
    return self && self->ref_count > 0 && (allow_sealed || !self->is_sealed);
}

static void
_idx_obj_id_hash_update(const NMDedupMultiIdxType *idx_type,
                        const NMDedupMultiObj     *obj,
                        NMHashState               *h)
{
    nmp_object_id_hash_update((NMPObject *) obj, h);
}

static gboolean
_idx_obj_id_equal(const NMDedupMultiIdxType *idx_type,
                  const NMDedupMultiObj     *obj_a,
                  const NMDedupMultiObj     *obj_b)
{
    return nmp_object_id_equal((NMPObject *) obj_a, (NMPObject *) obj_b);
}

static void
_idx_type_init(DedupMultiIdxType *idx_type, NMPObjectType obj_type)
{
    static const NMDedupMultiIdxTypeClass idx_type_class = {
        .idx_obj_id_hash_update = _idx_obj_id_hash_update,
        .idx_obj_id_equal       = _idx_obj_id_equal,
    };

    nm_dedup_multi_idx_type_init(&idx_type->parent, &idx_type_class);
    idx_type->obj_type = obj_type;
}

NML3ConfigData *
nm_l3_config_data_new(NMDedupMultiIndex *multi_idx, int ifindex, NMIPConfigSource source)
{
    NML3ConfigData *self;

    nm_assert(multi_idx);
    nm_assert(ifindex > 0);
    nm_assert(source == NM_IP_CONFIG_SOURCE_UNKNOWN
              || (source >= NM_IP_CONFIG_SOURCE_KERNEL && source <= NM_IP_CONFIG_SOURCE_USER));

    self  = g_slice_new(NML3ConfigData);
    *self = (NML3ConfigData){
        .ref_count                     = 1,
        .ifindex                       = ifindex,
        .multi_idx                     = nm_dedup_multi_index_ref(multi_idx),
        .mdns                          = NM_SETTING_CONNECTION_MDNS_DEFAULT,
        .llmnr                         = NM_SETTING_CONNECTION_LLMNR_DEFAULT,
        .dns_over_tls                  = NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT,
        .flags                         = NM_L3_CONFIG_DAT_FLAGS_NONE,
        .metered                       = NM_TERNARY_DEFAULT,
        .proxy_browser_only            = NM_TERNARY_DEFAULT,
        .proxy_method                  = NM_PROXY_CONFIG_METHOD_UNKNOWN,
        .route_table_sync_4            = NM_IP_ROUTE_TABLE_SYNC_MODE_NONE,
        .route_table_sync_6            = NM_IP_ROUTE_TABLE_SYNC_MODE_NONE,
        .never_default_6               = NM_OPTION_BOOL_DEFAULT,
        .never_default_4               = NM_OPTION_BOOL_DEFAULT,
        .source                        = source,
        .ip6_privacy                   = NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
        .ndisc_hop_limit_set           = FALSE,
        .ndisc_reachable_time_msec_set = FALSE,
        .ndisc_retrans_timer_msec_set  = FALSE,
    };

    _idx_type_init(&self->idx_addresses_4, NMP_OBJECT_TYPE_IP4_ADDRESS);
    _idx_type_init(&self->idx_addresses_6, NMP_OBJECT_TYPE_IP6_ADDRESS);
    _idx_type_init(&self->idx_routes_4, NMP_OBJECT_TYPE_IP4_ROUTE);
    _idx_type_init(&self->idx_routes_6, NMP_OBJECT_TYPE_IP6_ROUTE);

    return self;
}

const NML3ConfigData *
nm_l3_config_data_ref(const NML3ConfigData *self)
{
    if (self) {
        nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
        ((NML3ConfigData *) self)->ref_count++;
    }
    return self;
}

const NML3ConfigData *
nm_l3_config_data_ref_and_seal(const NML3ConfigData *self)
{
    if (self) {
        nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
        ((NML3ConfigData *) self)->is_sealed = TRUE;
        ((NML3ConfigData *) self)->ref_count++;
    }
    return self;
}

const NML3ConfigData *
nm_l3_config_data_seal(const NML3ConfigData *self)
{
    if (self) {
        nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
        ((NML3ConfigData *) self)->is_sealed = TRUE;
    }
    return self;
}

gboolean
nm_l3_config_data_is_sealed(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
    return self->is_sealed;
}

void
nm_l3_config_data_unref(const NML3ConfigData *self)
{
    NML3ConfigData *mutable;

    if (!self)
        return;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    /* NML3ConfigData aims to be an immutable, ref-counted type. The mode of operation
     * is to create/initialize the instance once, then seal it and pass around the reference.
     *
     * That means, also ref/unref operate on const pointers (otherwise, you'd have to cast all
     * the time). Hence, we cast away the constness during ref/unref/seal operations. */

    mutable = (NML3ConfigData *) self;

    if (--mutable->ref_count > 0)
        return;

    nm_dedup_multi_index_remove_idx(mutable->multi_idx, &mutable->idx_addresses_4.parent);
    nm_dedup_multi_index_remove_idx(mutable->multi_idx, &mutable->idx_addresses_6.parent);
    nm_dedup_multi_index_remove_idx(mutable->multi_idx, &mutable->idx_routes_4.parent);
    nm_dedup_multi_index_remove_idx(mutable->multi_idx, &mutable->idx_routes_6.parent);

    nmp_object_unref(mutable->best_default_route_4);
    nmp_object_unref(mutable->best_default_route_6);

    nm_clear_pointer(&mutable->wins, g_array_unref);
    nm_clear_pointer(&mutable->nis_servers, g_array_unref);

    nm_clear_pointer(&mutable->dhcp_lease_4, nm_dhcp_lease_unref);
    nm_clear_pointer(&mutable->dhcp_lease_6, nm_dhcp_lease_unref);

    nm_clear_pointer(&mutable->nameservers_4, g_array_unref);
    nm_clear_pointer(&mutable->nameservers_6, g_array_unref);

    nm_clear_pointer(&mutable->domains_4, g_ptr_array_unref);
    nm_clear_pointer(&mutable->domains_6, g_ptr_array_unref);

    nm_clear_pointer(&mutable->searches_4, g_ptr_array_unref);
    nm_clear_pointer(&mutable->searches_6, g_ptr_array_unref);

    nm_clear_pointer(&mutable->dns_options_4, g_ptr_array_unref);
    nm_clear_pointer(&mutable->dns_options_6, g_ptr_array_unref);

    nm_dedup_multi_index_unref(mutable->multi_idx);

    nm_ref_string_unref(mutable->nis_domain);
    nm_ref_string_unref(mutable->proxy_pac_url);
    nm_ref_string_unref(mutable->proxy_pac_script);

    nm_g_slice_free(mutable);
}

/*****************************************************************************/

static const NMDedupMultiEntry *
_lookup_route(const NMDedupMultiIndex *multi_idx,
              const DedupMultiIdxType *idx_type,
              const NMPObject         *needle)
{
    const NMDedupMultiEntry *entry;

    nm_assert(multi_idx);
    nm_assert(idx_type);
    nm_assert(NM_IN_SET(idx_type->obj_type, NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
    nm_assert(NMP_OBJECT_GET_TYPE(needle) == idx_type->obj_type);

    entry = nm_dedup_multi_index_lookup_obj(multi_idx, &idx_type->parent, needle);
    nm_assert(!entry
              || (NMP_OBJECT_GET_TYPE(needle) == NMP_OBJECT_TYPE_IP4_ROUTE
                  && nm_platform_ip4_route_cmp(NMP_OBJECT_CAST_IP4_ROUTE(entry->obj),
                                               NMP_OBJECT_CAST_IP4_ROUTE(needle),
                                               NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID)
                         == 0)
              || (NMP_OBJECT_GET_TYPE(needle) == NMP_OBJECT_TYPE_IP6_ROUTE
                  && nm_platform_ip6_route_cmp(NMP_OBJECT_CAST_IP6_ROUTE(entry->obj),
                                               NMP_OBJECT_CAST_IP6_ROUTE(needle),
                                               NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID)
                         == 0));

    return entry;
}

const NMDedupMultiEntry *
nm_l3_config_data_lookup_route_obj(const NML3ConfigData *self, const NMPObject *needle)
{
    gboolean IS_IPv4;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert(NM_IN_SET(NMP_OBJECT_GET_TYPE(needle),
                        NMP_OBJECT_TYPE_IP4_ROUTE,
                        NMP_OBJECT_TYPE_IP6_ROUTE));

    IS_IPv4 = NM_IS_IPv4(NMP_OBJECT_GET_ADDR_FAMILY(needle));
    return _lookup_route(self->multi_idx, &self->idx_routes_x[IS_IPv4], needle);
}

const NMDedupMultiEntry *
nm_l3_config_data_lookup_route(const NML3ConfigData    *self,
                               int                      addr_family,
                               const NMPlatformIPRoute *needle)
{
    const int IS_IPv4 = NM_IS_IPv4(addr_family);
    NMPObject obj_stack;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);
    nm_assert(needle);

    return _lookup_route(
        self->multi_idx,
        &self->idx_routes_x[IS_IPv4],
        nmp_object_stackinit(&obj_stack, NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4), needle));
}

const NMDedupMultiIdxType *
nm_l3_config_data_lookup_index(const NML3ConfigData *self, NMPObjectType obj_type)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    switch (obj_type) {
    case NMP_OBJECT_TYPE_IP4_ADDRESS:
        return &self->idx_addresses_4.parent;
    case NMP_OBJECT_TYPE_IP6_ADDRESS:
        return &self->idx_addresses_6.parent;
    case NMP_OBJECT_TYPE_IP4_ROUTE:
        return &self->idx_routes_4.parent;
    case NMP_OBJECT_TYPE_IP6_ROUTE:
        return &self->idx_routes_6.parent;
    default:
        return nm_assert_unreachable_val(NULL);
    }
}

const NMDedupMultiHeadEntry *
nm_l3_config_data_lookup_objs(const NML3ConfigData *self, NMPObjectType obj_type)
{
    if (!self)
        return NULL;
    return nm_dedup_multi_index_lookup_head(self->multi_idx,
                                            nm_l3_config_data_lookup_index(self, obj_type),
                                            NULL);
}

const NMDedupMultiEntry *
nm_l3_config_data_lookup_obj(const NML3ConfigData *self, const NMPObject *obj)
{
    const NMDedupMultiIdxType *idx;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    idx = nm_l3_config_data_lookup_index(self, NMP_OBJECT_GET_TYPE(obj));

    return nm_dedup_multi_index_lookup_obj(self->multi_idx, idx, obj);
}

const NMPlatformIP4Address *
nm_l3_config_data_lookup_address_4(const NML3ConfigData *self,
                                   in_addr_t             addr,
                                   guint8                plen,
                                   in_addr_t             peer_addr)
{
    const NMDedupMultiEntry *head;
    NMPObject                obj_stack;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    nmp_object_stackinit_id_ip4_address(&obj_stack, self->ifindex, addr, plen, peer_addr);

    head = nm_l3_config_data_lookup_obj(self, &obj_stack);
    if (!head)
        return NULL;

    return NMP_OBJECT_CAST_IP4_ADDRESS(head->obj);
}

const NMPlatformIP6Address *
nm_l3_config_data_lookup_address_6(const NML3ConfigData *self, const struct in6_addr *addr)
{
    const NMDedupMultiEntry *head;
    NMPObject                obj_stack;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    /* this works only, because the primary key for a IPv6 address is the
     * ifindex and the "struct in6_addr". */
    nmp_object_stackinit_id_ip6_address(&obj_stack, self->ifindex, addr);

    head = nm_l3_config_data_lookup_obj(self, &obj_stack);
    if (!head)
        return NULL;

    return NMP_OBJECT_CAST_IP6_ADDRESS(head->obj);
}

const NMPObject *
nmtst_l3_config_data_get_obj_at(const NML3ConfigData *self, NMPObjectType obj_type, guint i)
{
    NMDedupMultiIter iter;
    guint            j;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    j = 0;
    nm_dedup_multi_iter_init(&iter, nm_l3_config_data_lookup_objs(self, obj_type));
    while (nm_dedup_multi_iter_next(&iter)) {
        nm_assert(iter.current);
        nm_assert(NMP_OBJECT_GET_TYPE(iter.current->obj) == obj_type);
        if (i == j)
            return iter.current->obj;
        j++;
    }

    g_return_val_if_reached(NULL);
}

/*****************************************************************************/

gboolean
nm_l3_config_data_has_routes_with_type_local(const NML3ConfigData *self, int addr_family)
{
    const int        IS_IPv4 = NM_IS_IPv4(addr_family);
    NML3ConfigData  *self_mutable;
    NMDedupMultiIter iter;
    const NMPObject *obj;
    gboolean         val;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);

    if (IS_IPv4) {
        if (G_LIKELY(self->has_routes_with_type_local_4_set))
            return self->has_routes_with_type_local_4_val;
    } else {
        if (G_LIKELY(self->has_routes_with_type_local_6_set))
            return self->has_routes_with_type_local_6_val;
    }

    val = FALSE;
    nm_l3_config_data_iter_obj_for_each (&iter, self, &obj, NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
        if (NMP_OBJECT_CAST_IP_ROUTE(obj)->type_coerced
            == nm_platform_route_type_coerce(RTN_LOCAL)) {
            val = TRUE;
            break;
        }
    }

    /* the value gets accumulated and cached. Doing that is also permissible to a
     * const/sealed instance. Hence, we cast the const-ness away. */
    self_mutable = (NML3ConfigData *) self;
    if (IS_IPv4) {
        self_mutable->has_routes_with_type_local_4_set = TRUE;
        self_mutable->has_routes_with_type_local_4_val = val;
    } else {
        self_mutable->has_routes_with_type_local_6_set = TRUE;
        self_mutable->has_routes_with_type_local_6_val = val;
    }

    return val;
}

/*****************************************************************************/

NMDedupMultiIndex *
nm_l3_config_data_get_multi_idx(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->multi_idx;
}

int
nm_l3_config_data_get_ifindex(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->ifindex;
}

/*****************************************************************************/

NML3ConfigDatFlags
nm_l3_config_data_get_flags(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->flags;
}

void
nm_l3_config_data_set_flags_full(NML3ConfigData    *self,
                                 NML3ConfigDatFlags flags,
                                 NML3ConfigDatFlags mask)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert(!NM_FLAGS_ANY(flags, ~mask));
    nm_assert(!NM_FLAGS_ANY(mask, ~NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES));

    self->flags = (self->flags & ~mask) | (flags & mask);
}

/*****************************************************************************/

const NMPObject *
nm_l3_config_data_get_first_obj(const NML3ConfigData *self,
                                NMPObjectType         obj_type,
                                gboolean (*predicate)(const NMPObject *obj))
{
    NMDedupMultiIter iter;
    const NMPObject *obj;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    nm_l3_config_data_iter_obj_for_each (&iter, self, &obj, obj_type) {
        if (!predicate || predicate(obj))
            return obj;
    }
    return NULL;
}

/*****************************************************************************/

static gboolean
_l3_config_data_add_obj(NMDedupMultiIndex      *multi_idx,
                        DedupMultiIdxType      *idx_type,
                        int                     ifindex,
                        const NMPObject        *obj_new,
                        const NMPlatformObject *pl_new,
                        NML3ConfigAddFlags      add_flags,
                        const NMPObject       **out_obj_old /* returns a reference! */,
                        const NMPObject       **out_obj_new /* does not return a reference */)
{
    NMPObject                obj_new_stackinit;
    const NMDedupMultiEntry *entry_old;
    const NMDedupMultiEntry *entry_new;

    nm_assert(nm_utils_is_power_of_two_or_zero(
        add_flags & (NM_L3_CONFIG_ADD_FLAGS_MERGE | NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE)));
    nm_assert(multi_idx);
    nm_assert(idx_type);
    nm_assert(ifindex > 0);
    nm_assert(NM_IN_SET(idx_type->obj_type,
                        NMP_OBJECT_TYPE_IP4_ADDRESS,
                        NMP_OBJECT_TYPE_IP4_ROUTE,
                        NMP_OBJECT_TYPE_IP6_ADDRESS,
                        NMP_OBJECT_TYPE_IP6_ROUTE));
    nm_assert((!!obj_new) != (!!pl_new));

    if (NM_IN_SET(idx_type->obj_type, NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE)) {
        const NMPlatformIPRoute *r;

        r = obj_new ? NMP_OBJECT_CAST_IP_ROUTE(obj_new) : (NMPlatformIPRoute *) pl_new;

        if (nm_platform_route_type_is_nodev(nm_platform_route_type_uncoerce(r->type_coerced))) {
            /* such routes don't have a device/next-hop. We track them without ifindex. */
            ifindex = 0;
        }
    }

    /* we go through extra lengths to accept a full obj_new object. That one,
     * can be reused by increasing the ref-count. We thus accept any ifindex, and
     * set it here. */
    if (!obj_new) {
        nm_assert(pl_new);
        obj_new = nmp_object_stackinit(&obj_new_stackinit, idx_type->obj_type, pl_new);
        NMP_OBJECT_CAST_OBJ_WITH_IFINDEX(&obj_new_stackinit)->ifindex = ifindex;
    } else {
        nm_assert(!pl_new);
        nm_assert(NMP_OBJECT_GET_TYPE(obj_new) == idx_type->obj_type);
        if (NMP_OBJECT_CAST_OBJ_WITH_IFINDEX(obj_new)->ifindex != ifindex) {
            obj_new = nmp_object_stackinit_obj(&obj_new_stackinit, obj_new);
            NMP_OBJECT_CAST_OBJ_WITH_IFINDEX(&obj_new_stackinit)->ifindex = ifindex;
        }
    }
    nm_assert(NMP_OBJECT_GET_TYPE(obj_new) == idx_type->obj_type);
    nm_assert(nmp_object_is_alive(obj_new));

    entry_old = nm_dedup_multi_index_lookup_obj(multi_idx, &idx_type->parent, obj_new);

    if (entry_old) {
        gboolean         modified = FALSE;
        const NMPObject *obj_old  = entry_old->obj;

        if (NM_FLAGS_HAS(add_flags, NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE)) {
            nm_dedup_multi_entry_set_dirty(entry_old, FALSE);
            goto append_force_and_out;
        }

        if (nmp_object_equal(obj_new, obj_old)) {
            nm_dedup_multi_entry_set_dirty(entry_old, FALSE);
            goto append_force_and_out;
        }

        if (NM_FLAGS_HAS(add_flags, NM_L3_CONFIG_ADD_FLAGS_MERGE)) {
            switch (idx_type->obj_type) {
            case NMP_OBJECT_TYPE_IP4_ADDRESS:
            case NMP_OBJECT_TYPE_IP6_ADDRESS:
                /* for addresses that we read from the kernel, we keep the timestamps as defined
                 * by the previous source (item_old). The reason is, that the other source configured the lifetimes
                 * with "what should be" and the kernel values are "what turned out after configuring it".
                 *
                 * For other sources, the longer lifetime wins. */
                if ((obj_new->ip_address.addr_source == NM_IP_CONFIG_SOURCE_KERNEL
                     && obj_old->ip_address.addr_source != NM_IP_CONFIG_SOURCE_KERNEL)
                    || nm_platform_ip_address_cmp_expiry(NMP_OBJECT_CAST_IP_ADDRESS(obj_old),
                                                         NMP_OBJECT_CAST_IP_ADDRESS(obj_new))
                           > 0) {
                    obj_new = nmp_object_stackinit_obj(&obj_new_stackinit, obj_new);
                    obj_new_stackinit.ip_address.timestamp =
                        NMP_OBJECT_CAST_IP_ADDRESS(obj_old)->timestamp;
                    obj_new_stackinit.ip_address.lifetime =
                        NMP_OBJECT_CAST_IP_ADDRESS(obj_old)->lifetime;
                    obj_new_stackinit.ip_address.preferred =
                        NMP_OBJECT_CAST_IP_ADDRESS(obj_old)->preferred;
                    modified = TRUE;
                }

                /* keep the maximum addr_source. */
                if (obj_new->ip_address.addr_source < obj_old->ip_address.addr_source) {
                    obj_new = nmp_object_stackinit_obj(&obj_new_stackinit, obj_new);
                    obj_new_stackinit.ip_address.addr_source = obj_old->ip_address.addr_source;
                    modified                                 = TRUE;
                }

                /* OR assume_config_once flag */
                if (obj_new->ip_address.a_assume_config_once
                    && !obj_old->ip_address.a_assume_config_once) {
                    obj_new = nmp_object_stackinit_obj(&obj_new_stackinit, obj_new);
                    obj_new_stackinit.ip_address.a_assume_config_once = TRUE;
                    modified                                          = TRUE;
                }
                break;
            case NMP_OBJECT_TYPE_IP4_ROUTE:
            case NMP_OBJECT_TYPE_IP6_ROUTE:
                /* keep the maximum rt_source. */
                if (obj_new->ip_route.rt_source < obj_old->ip_route.rt_source) {
                    obj_new = nmp_object_stackinit_obj(&obj_new_stackinit, obj_new);
                    obj_new_stackinit.ip_route.rt_source = obj_old->ip_route.rt_source;
                    modified                             = TRUE;
                }

                /* OR assume_config_once flag */
                if (obj_new->ip_route.r_assume_config_once
                    && !obj_old->ip_route.r_assume_config_once) {
                    obj_new = nmp_object_stackinit_obj(&obj_new_stackinit, obj_new);
                    obj_new_stackinit.ip_route.r_assume_config_once = TRUE;
                    modified                                        = TRUE;
                }
                break;
            default:
                nm_assert_not_reached();
                break;
            }

            if (modified && nmp_object_equal(obj_new, obj_old)) {
                nm_dedup_multi_entry_set_dirty(entry_old, FALSE);
                goto append_force_and_out;
            }
        }
    }

    if (!nm_dedup_multi_index_add_full(multi_idx,
                                       &idx_type->parent,
                                       obj_new,
                                       NM_FLAGS_HAS(add_flags, NM_L3_CONFIG_ADD_FLAGS_APPEND_FORCE)
                                           ? NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE
                                           : NM_DEDUP_MULTI_IDX_MODE_APPEND,
                                       NULL,
                                       entry_old ?: NM_DEDUP_MULTI_ENTRY_MISSING,
                                       NULL,
                                       &entry_new,
                                       out_obj_old)) {
        nm_assert_not_reached();
        NM_SET_OUT(out_obj_new, NULL);
        return FALSE;
    }

    NM_SET_OUT(out_obj_new, entry_new->obj);
    return TRUE;

append_force_and_out:
    NM_SET_OUT(out_obj_old, nmp_object_ref(entry_old->obj));
    NM_SET_OUT(out_obj_new, entry_old->obj);
    if (NM_FLAGS_HAS(add_flags, NM_L3_CONFIG_ADD_FLAGS_APPEND_FORCE)) {
        if (nm_dedup_multi_entry_reorder(entry_old, NULL, TRUE))
            return TRUE;
    }
    return FALSE;
}

static const NMPObject *
_l3_config_best_default_route_find_better(const NMPObject *obj_cur, const NMPObject *obj_cmp)
{
    nm_assert(!obj_cur
              || NM_IN_SET(NMP_OBJECT_GET_TYPE(obj_cur),
                           NMP_OBJECT_TYPE_IP4_ROUTE,
                           NMP_OBJECT_TYPE_IP6_ROUTE));
    nm_assert(!obj_cmp
              || (!obj_cur
                  && NM_IN_SET(NMP_OBJECT_GET_TYPE(obj_cmp),
                               NMP_OBJECT_TYPE_IP4_ROUTE,
                               NMP_OBJECT_TYPE_IP6_ROUTE))
              || NMP_OBJECT_GET_TYPE(obj_cur) == NMP_OBJECT_GET_TYPE(obj_cmp));
    nm_assert(!obj_cur || nmp_object_ip_route_is_best_default_route(obj_cur));

    /* assumes that @obj_cur is already the best default route (or NULL). It checks whether
     * @obj_cmp is also a default route and returns the best of both. */
    if (obj_cmp && nmp_object_ip_route_is_best_default_route(obj_cmp)) {
        guint32 metric_cur, metric_cmp;

        if (!obj_cur)
            return obj_cmp;

        if (obj_cur == obj_cmp)
            return obj_cmp;

        metric_cur = NMP_OBJECT_CAST_IP_ROUTE(obj_cur)->metric;
        metric_cmp = NMP_OBJECT_CAST_IP_ROUTE(obj_cmp)->metric;

        if (metric_cmp < metric_cur)
            return obj_cmp;

        if (metric_cmp == metric_cur) {
            int c;

            /* Routes have the same metric. We still want to deterministically
             * prefer one or the other. It's important to consistently choose one
             * or the other, so that the order doesn't matter how routes are added
             * (and merged). */
            c = nmp_object_cmp(obj_cur, obj_cmp);
            if (c != 0)
                return c < 0 ? obj_cur : obj_cmp;

            /* as last resort, compare pointers. */
            if (((uintptr_t) ((void *) (obj_cmp))) < ((uintptr_t) ((void *) (obj_cur))))
                return obj_cmp;
        }
    }
    return obj_cur;
}

gboolean
nm_l3_config_data_add_address_full(NML3ConfigData            *self,
                                   int                        addr_family,
                                   const NMPObject           *obj_new,
                                   const NMPlatformIPAddress *pl_new,
                                   NML3ConfigAddFlags         add_flags,
                                   const NMPObject          **out_obj_new)
{
    const NMPObject *new;
    gboolean changed;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);
    nm_assert((!pl_new) != (!obj_new));
    nm_assert(!obj_new || NMP_OBJECT_GET_ADDR_FAMILY(obj_new) == addr_family);

    changed = _l3_config_data_add_obj(self->multi_idx,
                                      &self->idx_addresses_x[NM_IS_IPv4(addr_family)],
                                      self->ifindex,
                                      obj_new,
                                      (const NMPlatformObject *) pl_new,
                                      add_flags,
                                      NULL,
                                      &new);
    NM_SET_OUT(out_obj_new, nmp_object_ref(new));
    return changed;
}

static gboolean
_l3_config_best_default_route_merge(const NMPObject **best_default_route,
                                    const NMPObject  *new_candidate)
{
    new_candidate = _l3_config_best_default_route_find_better(*best_default_route, new_candidate);
    return nmp_object_ref_set(best_default_route, new_candidate);
}

gboolean
nm_l3_config_data_add_route_full(NML3ConfigData          *self,
                                 int                      addr_family,
                                 const NMPObject         *obj_new,
                                 const NMPlatformIPRoute *pl_new,
                                 NML3ConfigAddFlags       add_flags,
                                 const NMPObject        **out_obj_new,
                                 gboolean                *out_changed_best_default_route)
{
    const int                       IS_IPv4 = NM_IS_IPv4(addr_family);
    nm_auto_nmpobj const NMPObject *obj_old = NULL;
    const NMPObject                *obj_new_2;
    gboolean                        changed                    = FALSE;
    gboolean                        changed_best_default_route = FALSE;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);
    nm_assert((!pl_new) != (!obj_new));
    nm_assert(!pl_new || _route_valid(addr_family, pl_new));
    nm_assert(!obj_new
              || (NMP_OBJECT_GET_ADDR_FAMILY(obj_new) == addr_family
                  && _route_valid(addr_family, NMP_OBJECT_CAST_IP_ROUTE(obj_new))));

    if (IS_IPv4)
        self->has_routes_with_type_local_4_set = FALSE;
    else
        self->has_routes_with_type_local_6_set = FALSE;
    if (_l3_config_data_add_obj(self->multi_idx,
                                &self->idx_routes_x[NM_IS_IPv4(addr_family)],
                                self->ifindex,
                                obj_new,
                                (const NMPlatformObject *) pl_new,
                                add_flags,
                                &obj_old,
                                &obj_new_2)) {
        if (self->best_default_route_x[IS_IPv4] == obj_old && obj_old != obj_new_2) {
            changed_best_default_route = TRUE;
            nm_clear_nmp_object(&self->best_default_route_x[IS_IPv4]);
        }

        if (_l3_config_best_default_route_merge(&self->best_default_route_x[IS_IPv4], obj_new_2))
            changed_best_default_route = TRUE;

        changed = TRUE;
    }

    NM_SET_OUT(out_obj_new, nmp_object_ref(obj_new_2));
    NM_SET_OUT(out_changed_best_default_route, changed_best_default_route);
    return changed;
}

const NMPObject *
nm_l3_config_data_get_best_default_route(const NML3ConfigData *self, int addr_family)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    switch (addr_family) {
    case AF_INET:
        return self->best_default_route_4;
    case AF_INET6:
        return self->best_default_route_6;
    case AF_UNSPEC:
        return self->best_default_route_4 ?: self->best_default_route_6;
    }
    return nm_assert_unreachable_val(NULL);
}

/*****************************************************************************/

static gboolean
_check_and_add_domain(GPtrArray **p_arr, const char *domain)
{
    gs_free char *copy = NULL;
    gsize         len;

    nm_assert(p_arr);
    g_return_val_if_fail(domain, FALSE);

    if (domain[0] == '\0')
        return FALSE;

    if (domain[0] == '.' || strstr(domain, ".."))
        return FALSE;

    len = strlen(domain);
    if (domain[len - 1] == '.') {
        copy   = g_strndup(domain, len - 1);
        domain = copy;
    }

    if (nm_strv_ptrarray_contains(*p_arr, domain))
        return FALSE;

    nm_strv_ptrarray_add_string_take(nm_strv_ptrarray_ensure(p_arr),
                                     g_steal_pointer(&copy) ?: g_strdup(domain));
    return TRUE;
}

gconstpointer
nm_l3_config_data_get_nameservers(const NML3ConfigData *self, int addr_family, guint *out_len)
{
    nm_assert(!self || _NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);
    nm_assert(out_len);

    if (!self) {
        *out_len = 0;
        return NULL;
    }

    return _garray_inaddr_get(self->nameservers_x[NM_IS_IPv4(addr_family)], out_len);
}

gboolean
nm_l3_config_data_add_nameserver(NML3ConfigData                        *self,
                                 int                                    addr_family,
                                 gconstpointer /* (const NMIPAddr *) */ nameserver)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);
    nm_assert(nameserver);

    return _garray_inaddr_add(&self->nameservers_x[NM_IS_IPv4(addr_family)],
                              addr_family,
                              nameserver);
}

gboolean
nm_l3_config_data_clear_nameservers(NML3ConfigData *self, int addr_family)
{
    gs_unref_array GArray *old = NULL;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    old = g_steal_pointer(&self->nameservers_x[NM_IS_IPv4(addr_family)]);
    return (nm_g_array_len(old) > 0);
}

const in_addr_t *
nm_l3_config_data_get_wins(const NML3ConfigData *self, guint *out_len)
{
    nm_assert(!self || _NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert(out_len);

    if (!self) {
        *out_len = 0;
        return NULL;
    }

    return _garray_inaddr_get(self->wins, out_len);
}

gboolean
nm_l3_config_data_add_wins(NML3ConfigData *self, in_addr_t wins)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    return _garray_inaddr_add(&self->wins, AF_INET, &wins);
}

const in_addr_t *
nm_l3_config_data_get_nis_servers(const NML3ConfigData *self, guint *out_len)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return _garray_inaddr_get(self->nis_servers, out_len);
}

gboolean
nm_l3_config_data_add_nis_server(NML3ConfigData *self, in_addr_t nis_server)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    return _garray_inaddr_add(&self->nis_servers, AF_INET, &nis_server);
}

const char *
nm_l3_config_data_get_nis_domain(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return nm_ref_string_get_str(self->nis_domain);
}

gboolean
nm_l3_config_data_set_nis_domain(NML3ConfigData *self, const char *nis_domain)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    return nm_ref_string_reset_str(&self->nis_domain, nis_domain);
}

const char *const *
nm_l3_config_data_get_domains(const NML3ConfigData *self, int addr_family, guint *out_len)
{
    nm_assert(!self || _NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);
    nm_assert(out_len);

    if (!self) {
        *out_len = 0;
        return NULL;
    }

    return nm_strv_ptrarray_get_unsafe(self->domains_x[NM_IS_IPv4(addr_family)], out_len);
}

gboolean
nm_l3_config_data_add_domain(NML3ConfigData *self, int addr_family, const char *domain)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    return _check_and_add_domain(&self->domains_x[NM_IS_IPv4(addr_family)], domain);
}

const char *const *
nm_l3_config_data_get_searches(const NML3ConfigData *self, int addr_family, guint *out_len)
{
    nm_assert(!self || _NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);
    nm_assert(out_len);

    if (!self) {
        *out_len = 0;
        return NULL;
    }

    return nm_strv_ptrarray_get_unsafe(self->searches_x[NM_IS_IPv4(addr_family)], out_len);
}

gboolean
nm_l3_config_data_add_search(NML3ConfigData *self, int addr_family, const char *search)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    return _check_and_add_domain(&self->searches_x[NM_IS_IPv4(addr_family)], search);
}

gboolean
nm_l3_config_data_clear_searches(NML3ConfigData *self, int addr_family)
{
    gs_unref_ptrarray GPtrArray *old = NULL;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    old = g_steal_pointer(&self->searches_x[NM_IS_IPv4(addr_family)]);
    return (nm_g_ptr_array_len(old) > 0);
}

gboolean
nm_l3_config_data_add_dns_option(NML3ConfigData *self, int addr_family, const char *dns_option)
{
    GPtrArray **p_arr;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    g_return_val_if_fail(dns_option, FALSE);

    if (dns_option[0] == '\0')
        return FALSE;

    p_arr = &self->dns_options_x[NM_IS_IPv4(addr_family)];

    if (nm_strv_ptrarray_contains(*p_arr, dns_option))
        return FALSE;

    nm_strv_ptrarray_add_string_dup(nm_strv_ptrarray_ensure(p_arr), dns_option);
    return TRUE;
}

const char *const *
nm_l3_config_data_get_dns_options(const NML3ConfigData *self, int addr_family, guint *out_len)
{
    nm_assert(!self || _NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);
    nm_assert(out_len);

    if (!self) {
        *out_len = 0;
        return NULL;
    }

    return nm_strv_ptrarray_get_unsafe(self->dns_options_x[NM_IS_IPv4(addr_family)], out_len);
}

gboolean
nm_l3_config_data_get_dns_priority(const NML3ConfigData *self, int addr_family, int *out_prio)
{
    switch (addr_family) {
    case AF_UNSPEC:
        if (NM_FLAGS_ANY(self->flags, NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_4)) {
            if (NM_FLAGS_ANY(self->flags, NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_6)) {
                NM_SET_OUT(out_prio, MIN(self->dns_priority_4, self->dns_priority_6));
                return TRUE;
            }
            NM_SET_OUT(out_prio, self->dns_priority_4);
            return TRUE;
        }
        if (NM_FLAGS_ANY(self->flags, NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_6)) {
            NM_SET_OUT(out_prio, self->dns_priority_6);
            return TRUE;
        }
        break;
    case AF_INET:
        if (NM_FLAGS_ANY(self->flags, NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_4)) {
            NM_SET_OUT(out_prio, self->dns_priority_4);
            return TRUE;
        }
        break;
    case AF_INET6:
        if (NM_FLAGS_ANY(self->flags, NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_6)) {
            NM_SET_OUT(out_prio, self->dns_priority_6);
            return TRUE;
        }
        break;
    default:
        nm_assert_not_reached();
    }
    NM_SET_OUT(out_prio, 0);
    return FALSE;
}

gboolean
nm_l3_config_data_set_dns_priority(NML3ConfigData *self, int addr_family, int dns_priority)
{
    const int                IS_IPv4 = NM_IS_IPv4(addr_family);
    const NML3ConfigDatFlags has_dns_priority_flag =
        NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY(IS_IPv4);

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    if (self->dns_priority_x[IS_IPv4] == dns_priority
        && NM_FLAGS_ANY(self->flags, has_dns_priority_flag))
        return FALSE;

    self->flags |= has_dns_priority_flag;
    self->dns_priority_x[IS_IPv4] = dns_priority;
    return TRUE;
}

NMSettingConnectionMdns
nm_l3_config_data_get_mdns(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->mdns;
}

gboolean
nm_l3_config_data_set_mdns(NML3ConfigData *self, NMSettingConnectionMdns mdns)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (self->mdns == mdns)
        return FALSE;

    self->mdns = mdns;
    return TRUE;
}

NMSettingConnectionLlmnr
nm_l3_config_data_get_llmnr(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->llmnr;
}

gboolean
nm_l3_config_data_set_llmnr(NML3ConfigData *self, NMSettingConnectionLlmnr llmnr)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (self->llmnr == llmnr)
        return FALSE;

    self->llmnr = llmnr;
    return TRUE;
}

NMSettingConnectionDnsOverTls
nm_l3_config_data_get_dns_over_tls(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->dns_over_tls;
}

gboolean
nm_l3_config_data_set_dns_over_tls(NML3ConfigData *self, NMSettingConnectionDnsOverTls dns_over_tls)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (self->dns_over_tls == dns_over_tls)
        return FALSE;

    self->dns_over_tls = dns_over_tls;
    return TRUE;
}

NMIPRouteTableSyncMode
nm_l3_config_data_get_route_table_sync(const NML3ConfigData *self, int addr_family)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);

    return self->route_table_sync_x[NM_IS_IPv4(addr_family)];
}

gboolean
nm_l3_config_data_set_route_table_sync(NML3ConfigData        *self,
                                       int                    addr_family,
                                       NMIPRouteTableSyncMode route_table_sync)
{
    const int IS_IPv4 = NM_IS_IPv4(addr_family);

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    if (self->route_table_sync_x[IS_IPv4] == route_table_sync)
        return FALSE;

    self->route_table_sync_x[IS_IPv4] = route_table_sync;
    return TRUE;
}

NMTernary
nm_l3_config_data_get_never_default(const NML3ConfigData *self, int addr_family)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return NM_TERNARY_FROM_OPTION_BOOL(self->never_default_x[NM_IS_IPv4(addr_family)]);
}

gboolean
nm_l3_config_data_set_never_default(NML3ConfigData *self, int addr_family, NMTernary never_default)
{
    const int          IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMOptionBool v       = NM_TERNARY_TO_OPTION_BOOL(never_default);

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (self->never_default_x[IS_IPv4] == v)
        return FALSE;

    self->never_default_x[IS_IPv4] = v;
    return TRUE;
}

NMTernary
nm_l3_config_data_get_metered(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->metered;
}

gboolean
nm_l3_config_data_set_metered(NML3ConfigData *self, NMTernary metered)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_is_ternary(metered);

    if (self->metered == metered)
        return FALSE;

    self->metered = metered;
    return TRUE;
}

guint32
nm_l3_config_data_get_mtu(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->mtu;
}

gboolean
nm_l3_config_data_set_mtu(NML3ConfigData *self, guint32 mtu)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (self->mtu == mtu)
        return FALSE;

    self->mtu = mtu;
    return TRUE;
}

guint32
nm_l3_config_data_get_ip6_mtu(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->ip6_mtu;
}

gboolean
nm_l3_config_data_set_ip6_mtu(NML3ConfigData *self, guint32 ip6_mtu)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (self->ip6_mtu == ip6_mtu)
        return FALSE;

    self->ip6_mtu = ip6_mtu;
    return TRUE;
}

NMSettingIP6ConfigPrivacy
nm_l3_config_data_get_ip6_privacy(const NML3ConfigData *self)
{
    nm_assert(!self || _NM_IS_L3_CONFIG_DATA(self, TRUE));

    if (!self)
        return NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN;

    return self->ip6_privacy;
}

gboolean
nm_l3_config_data_set_ip6_privacy(NML3ConfigData *self, NMSettingIP6ConfigPrivacy ip6_privacy)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert(NM_IN_SET(ip6_privacy,
                        NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN,
                        NM_SETTING_IP6_CONFIG_PRIVACY_DISABLED,
                        NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_PUBLIC_ADDR,
                        NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR));

    if (self->ip6_privacy == ip6_privacy)
        return FALSE;
    self->ip6_privacy = ip6_privacy;
    nm_assert(self->ip6_privacy == ip6_privacy);
    return TRUE;
}

NMUtilsIPv6IfaceId
nm_l3_config_data_get_ip6_token(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->ip6_token;
}

gboolean
nm_l3_config_data_set_ip6_token(NML3ConfigData *self, NMUtilsIPv6IfaceId ipv6_token)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (self->ip6_token.id == ipv6_token.id)
        return FALSE;

    self->ip6_token.id = ipv6_token.id;
    return TRUE;
}

NMProxyConfigMethod
nm_l3_config_data_get_proxy_method(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->proxy_method;
}

gboolean
nm_l3_config_data_set_proxy_method(NML3ConfigData *self, NMProxyConfigMethod value)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert(NM_IN_SET(value,
                        NM_PROXY_CONFIG_METHOD_UNKNOWN,
                        NM_PROXY_CONFIG_METHOD_NONE,
                        NM_PROXY_CONFIG_METHOD_AUTO));

    if (self->proxy_method == value)
        return FALSE;

    self->proxy_method = value;
    return TRUE;
}

NMTernary
nm_l3_config_data_get_proxy_browser_only(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->proxy_browser_only;
}

gboolean
nm_l3_config_data_set_proxy_browser_only(NML3ConfigData *self, NMTernary value)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_is_ternary(value);

    if (value == self->proxy_browser_only)
        return FALSE;

    self->proxy_browser_only = value;
    return TRUE;
}

const char *
nm_l3_config_data_get_proxy_pac_url(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return nm_ref_string_get_str(self->proxy_pac_url);
}

gboolean
nm_l3_config_data_set_proxy_pac_url(NML3ConfigData *self, const char *value)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    return nm_ref_string_reset_str(&self->proxy_pac_url, value);
}

const char *
nm_l3_config_data_get_proxy_pac_script(const NML3ConfigData *self)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return nm_ref_string_get_str(self->proxy_pac_script);
}

gboolean
nm_l3_config_data_set_proxy_pac_script(NML3ConfigData *self, const char *value)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    return nm_ref_string_reset_str(&self->proxy_pac_script, value);
}

gboolean
nm_l3_config_data_get_ndisc_hop_limit(const NML3ConfigData *self, int *out_val)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    if (!self->ndisc_hop_limit_set) {
        NM_SET_OUT(out_val, 0);
        return FALSE;
    }
    NM_SET_OUT(out_val, self->ndisc_hop_limit_val);
    return TRUE;
}

gboolean
nm_l3_config_data_set_ndisc_hop_limit(NML3ConfigData *self, int val)
{
    if (self->ndisc_hop_limit_set && self->ndisc_hop_limit_val == val)
        return FALSE;
    self->ndisc_hop_limit_set = TRUE;
    self->ndisc_hop_limit_val = val;
    return TRUE;
}

gboolean
nm_l3_config_data_get_ndisc_reachable_time_msec(const NML3ConfigData *self, guint32 *out_val)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    if (!self->ndisc_reachable_time_msec_set) {
        NM_SET_OUT(out_val, 0);
        return FALSE;
    }
    NM_SET_OUT(out_val, self->ndisc_reachable_time_msec_val);
    return TRUE;
}

gboolean
nm_l3_config_data_set_ndisc_reachable_time_msec(NML3ConfigData *self, guint32 val)
{
    if (self->ndisc_reachable_time_msec_set && self->ndisc_reachable_time_msec_val == val)
        return FALSE;
    self->ndisc_reachable_time_msec_set = TRUE;
    self->ndisc_reachable_time_msec_val = val;
    return TRUE;
}

gboolean
nm_l3_config_data_get_ndisc_retrans_timer_msec(const NML3ConfigData *self, guint32 *out_val)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    if (!self->ndisc_retrans_timer_msec_set) {
        NM_SET_OUT(out_val, 0);
        return FALSE;
    }
    NM_SET_OUT(out_val, self->ndisc_retrans_timer_msec_val);
    return TRUE;
}

gboolean
nm_l3_config_data_set_ndisc_retrans_timer_msec(NML3ConfigData *self, guint32 val)
{
    if (self->ndisc_retrans_timer_msec_set && self->ndisc_retrans_timer_msec_val == val)
        return FALSE;
    self->ndisc_retrans_timer_msec_set = TRUE;
    self->ndisc_retrans_timer_msec_val = val;
    return TRUE;
}

/*****************************************************************************/

NMDhcpLease *
nm_l3_config_data_get_dhcp_lease(const NML3ConfigData *self, int addr_family)
{
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    return self->dhcp_lease_x[NM_IS_IPv4(addr_family)];
}

gboolean
nm_l3_config_data_set_dhcp_lease(NML3ConfigData *self, int addr_family, NMDhcpLease *lease)
{
    nm_auto_unref_dhcplease NMDhcpLease *lease_old = NULL;
    NMDhcpLease                        **p_lease;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    p_lease = &self->dhcp_lease_x[NM_IS_IPv4(addr_family)];

    if (*p_lease == lease)
        return FALSE;

    if (lease)
        nm_dhcp_lease_ref(lease);
    lease_old = *p_lease;
    *p_lease  = lease;
    return TRUE;
}

gboolean
nm_l3_config_data_set_dhcp_lease_from_options(NML3ConfigData *self,
                                              int             addr_family,
                                              GHashTable     *options_take)
{
    nm_auto_unref_dhcplease NMDhcpLease *lease     = NULL;
    nm_auto_unref_dhcplease NMDhcpLease *lease_old = NULL;
    NMDhcpLease                        **p_lease;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    if (options_take)
        lease = nm_dhcp_lease_new_from_options(g_steal_pointer(&options_take));

    p_lease = &self->dhcp_lease_x[NM_IS_IPv4(addr_family)];

    if (*p_lease == lease)
        return FALSE;

    lease_old = *p_lease;
    *p_lease  = g_steal_pointer(&lease);
    return TRUE;
}

/*****************************************************************************/

static int
_dedup_multi_index_cmp(const NML3ConfigData *a,
                       const NML3ConfigData *b,
                       NMPObjectType         obj_type,
                       gboolean              cmp_ifindex,
                       gboolean              cmp_full)
{
    const NMDedupMultiHeadEntry *h_a = nm_l3_config_data_lookup_objs(a, obj_type);
    const NMDedupMultiHeadEntry *h_b = nm_l3_config_data_lookup_objs(b, obj_type);
    NMDedupMultiIter             iter_a;
    NMDedupMultiIter             iter_b;

    /* We handle ignore_index via NMP_OBJECT_CMP_FLAGS_IGNORE_IFINDEX flag, which is
     * only implemented for certain types. */
    nm_assert(NM_IN_SET(obj_type,
                        NMP_OBJECT_TYPE_IP4_ADDRESS,
                        NMP_OBJECT_TYPE_IP6_ADDRESS,
                        NMP_OBJECT_TYPE_IP4_ROUTE,
                        NMP_OBJECT_TYPE_IP6_ROUTE));

    NM_CMP_SELF(h_a, h_b);

    NM_CMP_DIRECT(h_a->len, h_b->len);

    nm_assert(h_a->len > 0);

    nm_dedup_multi_iter_init(&iter_a, h_a);
    nm_dedup_multi_iter_init(&iter_b, h_b);

    while (TRUE) {
        const NMPObject *obj_a;
        const NMPObject *obj_b;
        gboolean         have_a;
        gboolean         have_b;

        have_a = nm_platform_dedup_multi_iter_next_obj(&iter_a, &obj_a, obj_type);
        if (!have_a) {
            nm_assert(!nm_platform_dedup_multi_iter_next_obj(&iter_b, &obj_b, obj_type));
            return 0;
        }

        have_b = nm_platform_dedup_multi_iter_next_obj(&iter_b, &obj_b, obj_type);
        nm_assert(have_b);

        if (cmp_full) {
            NM_CMP_RETURN(nmp_object_cmp_full(obj_a,
                                              obj_b,
                                              cmp_ifindex ? NMP_OBJECT_CMP_FLAGS_NONE
                                                          : NMP_OBJECT_CMP_FLAGS_IGNORE_IFINDEX));
        } else {
            if (cmp_ifindex) {
                NM_CMP_DIRECT(obj_a->obj_with_ifindex.ifindex, obj_b->obj_with_ifindex.ifindex);
            }

            switch (obj_type) {
            case NMP_OBJECT_TYPE_IP4_ADDRESS:
                NM_CMP_DIRECT(obj_a->ip4_address.plen, obj_b->ip4_address.plen);
                NM_CMP_DIRECT(obj_b->ip4_address.address, obj_b->ip4_address.address);
                NM_CMP_DIRECT(obj_b->ip4_address.peer_address, obj_b->ip4_address.peer_address);
                break;
            case NMP_OBJECT_TYPE_IP6_ADDRESS:
                NM_CMP_DIRECT(obj_a->ip6_address.plen, obj_b->ip6_address.plen);
                NM_CMP_DIRECT_IN6ADDR(&obj_a->ip6_address.address, &obj_b->ip6_address.address);
                break;
            case NMP_OBJECT_TYPE_IP4_ROUTE:
            {
                NMPlatformIP4Route ra = obj_a->ip4_route;
                NMPlatformIP4Route rb = obj_b->ip4_route;

                NM_CMP_DIRECT(ra.metric, rb.metric);
                NM_CMP_DIRECT(ra.plen, rb.plen);
                NM_CMP_RETURN_DIRECT(
                    nm_utils_ip4_address_same_prefix_cmp(ra.network, rb.network, ra.plen));
                break;
            }
            case NMP_OBJECT_TYPE_IP6_ROUTE:
            {
                NMPlatformIP6Route ra = obj_a->ip6_route;
                NMPlatformIP6Route rb = obj_b->ip6_route;

                NM_CMP_DIRECT(ra.metric, rb.metric);
                NM_CMP_DIRECT(ra.plen, rb.plen);
                NM_CMP_RETURN_DIRECT(
                    nm_utils_ip6_address_same_prefix_cmp(&ra.network, &rb.network, ra.plen));
                break;
            }
            default:
                nm_assert_not_reached();
            }
        }
    }
}

static const NML3ConfigData *
get_empty_l3cd(void)
{
    static NML3ConfigData *empty_l3cd;

    if (!empty_l3cd) {
        empty_l3cd =
            nm_l3_config_data_new(nm_dedup_multi_index_new(), 1, NM_IP_CONFIG_SOURCE_UNKNOWN);
        empty_l3cd->ifindex = 0;
    }

    return empty_l3cd;
}

int
nm_l3_config_data_cmp_full(const NML3ConfigData *a,
                           const NML3ConfigData *b,
                           NML3ConfigCmpFlags    flags)
{
    int IS_IPv4;

    if (a == b)
        return 0;

    if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ADDRESSES))
        flags |= NM_L3_CONFIG_CMP_FLAGS_ADDRESSES_ID;
    if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ROUTES))
        flags |= NM_L3_CONFIG_CMP_FLAGS_ROUTES_ID;

    if (!a)
        a = get_empty_l3cd();
    if (!b)
        b = get_empty_l3cd();

    if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_IFINDEX))
        NM_CMP_DIRECT(a->ifindex, b->ifindex);

    if (NM_FLAGS_ANY(flags,
                     NM_L3_CONFIG_CMP_FLAGS_ADDRESSES | NM_L3_CONFIG_CMP_FLAGS_ADDRESSES_ID)) {
        NM_CMP_RETURN(
            _dedup_multi_index_cmp(a,
                                   b,
                                   NMP_OBJECT_TYPE_IP4_ADDRESS,
                                   NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_IFINDEX),
                                   NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ADDRESSES)));
        NM_CMP_RETURN(
            _dedup_multi_index_cmp(a,
                                   b,
                                   NMP_OBJECT_TYPE_IP6_ADDRESS,
                                   NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_IFINDEX),
                                   NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ADDRESSES)));
    }

    if (NM_FLAGS_ANY(flags, NM_L3_CONFIG_CMP_FLAGS_ROUTES | NM_L3_CONFIG_CMP_FLAGS_ROUTES_ID)) {
        NM_CMP_RETURN(_dedup_multi_index_cmp(a,
                                             b,
                                             NMP_OBJECT_TYPE_IP4_ROUTE,
                                             NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_IFINDEX),
                                             NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ROUTES)));
        NM_CMP_RETURN(_dedup_multi_index_cmp(a,
                                             b,
                                             NMP_OBJECT_TYPE_IP6_ROUTE,
                                             NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_IFINDEX),
                                             NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ROUTES)));
    }

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        const int        addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        const NMPObject *def_route_a = a->best_default_route_x[IS_IPv4];
        const NMPObject *def_route_b = b->best_default_route_x[IS_IPv4];

        NM_CMP_SELF(def_route_a, def_route_b);

        if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ROUTES)) {
            NM_CMP_RETURN(nmp_object_cmp_full(def_route_a,
                                              def_route_b,
                                              NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_IFINDEX)
                                                  ? NMP_OBJECT_CMP_FLAGS_NONE
                                                  : NMP_OBJECT_CMP_FLAGS_IGNORE_IFINDEX));
        } else if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_ROUTES_ID)) {
            if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_IFINDEX)) {
                NM_CMP_DIRECT(def_route_a->obj_with_ifindex.ifindex,
                              def_route_b->obj_with_ifindex.ifindex);
            }

            if (IS_IPv4) {
                NMPlatformIP4Route ra = def_route_a->ip4_route;
                NMPlatformIP4Route rb = def_route_b->ip4_route;

                NM_CMP_DIRECT(ra.metric, rb.metric);
                NM_CMP_DIRECT(ra.plen, rb.plen);
                NM_CMP_RETURN_DIRECT(
                    nm_utils_ip4_address_same_prefix_cmp(ra.network, rb.network, ra.plen));
            } else {
                NMPlatformIP6Route ra = def_route_a->ip6_route;
                NMPlatformIP6Route rb = def_route_b->ip6_route;

                NM_CMP_DIRECT(ra.metric, rb.metric);
                NM_CMP_DIRECT(ra.plen, rb.plen);
                NM_CMP_RETURN_DIRECT(
                    nm_utils_ip6_address_same_prefix_cmp(&ra.network, &rb.network, ra.plen));
            }
        }

        if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_DNS)) {
            NM_CMP_RETURN(_garray_inaddr_cmp(a->nameservers_x[IS_IPv4],
                                             b->nameservers_x[IS_IPv4],
                                             addr_family));
            NM_CMP_RETURN(nm_strv_ptrarray_cmp(a->domains_x[IS_IPv4], b->domains_x[IS_IPv4]));
            NM_CMP_RETURN(nm_strv_ptrarray_cmp(a->searches_x[IS_IPv4], b->searches_x[IS_IPv4]));
            NM_CMP_RETURN(
                nm_strv_ptrarray_cmp(a->dns_options_x[IS_IPv4], b->dns_options_x[IS_IPv4]));

            if (NM_FLAGS_ANY(a->flags, NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY(IS_IPv4)))
                NM_CMP_DIRECT(a->dns_priority_x[IS_IPv4], b->dns_priority_x[IS_IPv4]);
        }

        if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_OTHER)) {
            NM_CMP_RETURN(
                nm_utils_hashtable_cmp(nm_dhcp_lease_get_options(a->dhcp_lease_x[IS_IPv4]),
                                       nm_dhcp_lease_get_options(b->dhcp_lease_x[IS_IPv4]),
                                       TRUE,
                                       nm_strcmp_with_data,
                                       nm_strcmp_with_data,
                                       NULL));

            NM_CMP_DIRECT(a->route_table_sync_x[IS_IPv4], b->route_table_sync_x[IS_IPv4]);
            NM_CMP_DIRECT(a->never_default_x[IS_IPv4], b->never_default_x[IS_IPv4]);
        }
    }

    if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_DNS)) {
        NM_CMP_RETURN(_garray_inaddr_cmp(a->wins, b->wins, AF_INET));
        NM_CMP_RETURN(_garray_inaddr_cmp(a->nis_servers, b->nis_servers, AF_INET));
        NM_CMP_DIRECT_REF_STRING(a->nis_domain, b->nis_domain);
        NM_CMP_DIRECT(a->mdns, b->mdns);
        NM_CMP_DIRECT(a->llmnr, b->llmnr);
        NM_CMP_DIRECT(a->dns_over_tls, b->dns_over_tls);
    }

    if (NM_FLAGS_HAS(flags, NM_L3_CONFIG_CMP_FLAGS_OTHER)) {
        NM_CMP_DIRECT(a->flags, b->flags);
        NM_CMP_DIRECT(a->ip6_token.id, b->ip6_token.id);
        NM_CMP_DIRECT(a->mtu, b->mtu);
        NM_CMP_DIRECT(a->ip6_mtu, b->ip6_mtu);
        NM_CMP_DIRECT_UNSAFE(a->metered, b->metered);
        NM_CMP_DIRECT_UNSAFE(a->proxy_browser_only, b->proxy_browser_only);
        NM_CMP_DIRECT_UNSAFE(a->proxy_method, b->proxy_method);
        NM_CMP_DIRECT_REF_STRING(a->proxy_pac_url, b->proxy_pac_url);
        NM_CMP_DIRECT_REF_STRING(a->proxy_pac_script, b->proxy_pac_script);
        NM_CMP_DIRECT_UNSAFE(a->ip6_privacy, b->ip6_privacy);

        NM_CMP_DIRECT_UNSAFE(a->ndisc_hop_limit_set, b->ndisc_hop_limit_set);
        if (a->ndisc_hop_limit_set)
            NM_CMP_DIRECT(a->ndisc_hop_limit_val, b->ndisc_hop_limit_val);

        NM_CMP_DIRECT_UNSAFE(a->ndisc_reachable_time_msec_set, b->ndisc_reachable_time_msec_set);
        if (a->ndisc_reachable_time_msec_set)
            NM_CMP_DIRECT(a->ndisc_reachable_time_msec_val, b->ndisc_reachable_time_msec_val);

        NM_CMP_DIRECT_UNSAFE(a->ndisc_retrans_timer_msec_set, b->ndisc_retrans_timer_msec_set);
        if (a->ndisc_retrans_timer_msec_set)
            NM_CMP_DIRECT(a->ndisc_retrans_timer_msec_val, b->ndisc_retrans_timer_msec_val);

        NM_CMP_FIELD(a, b, source);
    }

    /* these fields are not considered by cmp():
     *
     * - multi_idx
     * - ref_count
     * - is_sealed
     */

    return 0;
}

/*****************************************************************************/

static const NMPObject *
_data_get_direct_route_for_host(const NML3ConfigData *self,
                                int                   addr_family,
                                gconstpointer         host,
                                guint32               route_table)
{
    const int                 IS_IPv4        = NM_IS_IPv4(addr_family);
    const NMPObject          *best_route_obj = NULL;
    const NMPlatformIPXRoute *best_route     = NULL;
    const NMPObject          *item_obj;
    NMDedupMultiIter          ipconf_iter;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));
    nm_assert_addr_family(addr_family);
    nm_assert(host);

    if (nm_ip_addr_is_null(addr_family, host))
        return NULL;

    nm_l3_config_data_iter_obj_for_each (&ipconf_iter,
                                         self,
                                         &item_obj,
                                         NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
        const NMPlatformIPXRoute *item = NMP_OBJECT_CAST_IPX_ROUTE(item_obj);

        if (!nm_ip_addr_is_null(addr_family,
                                nm_platform_ip_route_get_gateway(addr_family, &item->rx)))
            continue;

        if (best_route && best_route->rx.plen > item->rx.plen)
            continue;

        if (nm_platform_route_table_uncoerce(item->rx.table_coerced, TRUE) != route_table)
            continue;

        if (!nm_utils_ip_address_same_prefix(addr_family,
                                             host,
                                             item->rx.network_ptr,
                                             item->rx.plen))
            continue;

        if (best_route && best_route->rx.metric <= item->rx.metric)
            continue;

        best_route_obj = item_obj;
        best_route     = item;
    }
    return best_route_obj;
}

/*****************************************************************************/

/* Kernel likes to add device routes for all addresses. Normally, we want to suppress that
 * with IFA_F_NOPREFIXROUTE. But we also want to support kernels that don't support that
 * flag. So, we collect here all those routes that kernel might add but we don't want.
 * If the route shows up within a certain timeout of us configuring the address, we assume
 * that it was (undesirably) added by kernel and we remove it.
 *
 * The most common reason is that for each IPv4 address we want to add a corresponding device
 * route with the right ipv4.route-metric. The route that kernel adds has metric 0, so it is
 * undesired.
 *
 * FIXME(l3cfg): implement handling blacklisted routes.
 *
 * For IPv6, IFA_F_NOPREFIXROUTE is supported for a longer time and we don't do such a hack.
 */
GPtrArray *
nm_l3_config_data_get_blacklisted_ip4_routes(const NML3ConfigData *self, gboolean is_vrf)
{
    gs_unref_ptrarray GPtrArray *ip4_dev_route_blacklist = NULL;
    const NMPObject             *my_addr_obj;
    NMDedupMultiIter             iter;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, TRUE));

    /* For IPv6 slaac, we explicitly add the device-routes (onlink).
     * As we don't do that for IPv4 and manual IPv6 addresses. Add them here
     * as dependent routes. */

    nm_l3_config_data_iter_obj_for_each (&iter, self, &my_addr_obj, NMP_OBJECT_TYPE_IP4_ADDRESS) {
        const NMPlatformIP4Address *const my_addr = NMP_OBJECT_CAST_IP4_ADDRESS(my_addr_obj);
        in_addr_t                         network_4;
        NMPlatformIPXRoute                rx;

        nm_assert(my_addr->plen <= 32);
        if (my_addr->plen == 0)
            continue;

        network_4 = nm_utils_ip4_address_clear_host_address(my_addr->peer_address, my_addr->plen);

        if (nm_utils_ip4_address_is_zeronet(network_4)) {
            /* Kernel doesn't add device-routes for destinations that
             * start with 0.x.y.z. Skip them. */
            continue;
        }

        if (my_addr->plen == 32 && my_addr->address == my_addr->peer_address) {
            /* Kernel doesn't add device-routes for /32 addresses unless
             * they have a peer. */
            continue;
        }

        rx.r4 = (NMPlatformIP4Route){
            .ifindex       = self->ifindex,
            .rt_source     = NM_IP_CONFIG_SOURCE_KERNEL,
            .network       = network_4,
            .plen          = my_addr->plen,
            .pref_src      = my_addr->address,
            .table_coerced = nm_platform_route_table_coerce(RT_TABLE_MAIN),
            .metric        = NM_PLATFORM_ROUTE_METRIC_IP4_DEVICE_ROUTE,
            .scope_inv     = nm_platform_route_scope_inv(NM_RT_SCOPE_LINK),
        };
        nm_platform_ip_route_normalize(AF_INET, &rx.rx);

        if (nm_l3_config_data_lookup_route(self, AF_INET, &rx.rx)) {
            /* we track such a route explicitly. Don't blacklist it. */
            continue;
        }

        if (!ip4_dev_route_blacklist)
            ip4_dev_route_blacklist =
                g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);

        g_ptr_array_add(ip4_dev_route_blacklist, nmp_object_new(NMP_OBJECT_TYPE_IP4_ROUTE, &rx));
    }

    return g_steal_pointer(&ip4_dev_route_blacklist);
}

/*****************************************************************************/

void
nm_l3_config_data_add_dependent_onlink_routes(NML3ConfigData *self, int addr_family)
{
    gs_unref_ptrarray GPtrArray *extra_onlink_routes = NULL;
    const NMPObject             *obj_src;
    NMDedupMultiIter             iter;
    int                          IS_IPv4;
    guint                        i;

    if (addr_family == AF_UNSPEC) {
        nm_l3_config_data_add_dependent_onlink_routes(self, AF_INET);
        nm_l3_config_data_add_dependent_onlink_routes(self, AF_INET6);
        return;
    }

    IS_IPv4 = NM_IS_IPv4(addr_family);

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));

    /* For IPv6 slaac, we explicitly add the device-routes (onlink).
     * As we don't do that for IPv4 and manual IPv6 addresses. Add them here
     * as dependent routes. */

    nm_l3_config_data_iter_obj_for_each (&iter, self, &obj_src, NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
        const NMPlatformIPXRoute *route_src = NMP_OBJECT_CAST_IPX_ROUTE(obj_src);
        NMPObject                *new_route;
        NMPlatformIPXRoute       *new_r;
        const NMIPAddr           *p_gateway;

        p_gateway = nm_platform_ip_route_get_gateway(addr_family, &route_src->rx);

        if (nm_ip_addr_is_null(addr_family, p_gateway))
            continue;

        if (!NM_PLATFORM_IP_ROUTE_IS_DEFAULT(route_src)
            || _data_get_direct_route_for_host(
                self,
                addr_family,
                p_gateway,
                nm_platform_route_table_uncoerce(route_src->rx.table_coerced, TRUE)))
            continue;

        new_route = nmp_object_clone(obj_src, FALSE);
        new_r     = NMP_OBJECT_CAST_IPX_ROUTE(new_route);
        if (IS_IPv4) {
            new_r->r4.network = route_src->r4.gateway;
            new_r->r4.plen    = 32;
            new_r->r4.gateway = 0;
        } else {
            new_r->r6.network = route_src->r6.gateway;
            new_r->r6.plen    = 128;
            new_r->r6.gateway = in6addr_any;
        }

        /* we cannot add the route right away, because that invalidates the iteration. */
        if (!extra_onlink_routes)
            extra_onlink_routes = g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
        g_ptr_array_add(extra_onlink_routes, new_route);
    }
    if (extra_onlink_routes) {
        for (i = 0; i < extra_onlink_routes->len; i++) {
            nm_l3_config_data_add_route_full(self,
                                             addr_family,
                                             extra_onlink_routes->pdata[i],
                                             NULL,
                                             NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE,
                                             NULL,
                                             NULL);
        }
    }
}

void
nm_l3_config_data_add_dependent_device_routes(NML3ConfigData       *self,
                                              int                   addr_family,
                                              guint32               route_table,
                                              guint32               route_metric,
                                              gboolean              force_commit,
                                              const NML3ConfigData *source)
{
    const int          IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMPObject   *obj_src;
    NMPlatformIPXRoute rx;
    NMDedupMultiIter   iter;

    nm_assert_addr_family(addr_family);
    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert(_NM_IS_L3_CONFIG_DATA(source, TRUE));
    nm_assert(self != source);

    /* For IPv6 slaac, we explicitly add the device-routes (onlink) and track them
     * as regular routes in NML3ConfigData.
     *
     * For IPv4 and for manual IPv6 addresses we don't do that. Instead, add those
     * routes automatically afterwards.
     *
     * As route-table/metric is associated with the source l3cd, we need to process
     * all source l3cds separately. */

    nm_l3_config_data_iter_obj_for_each (&iter,
                                         source,
                                         &obj_src,
                                         NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4)) {
        const NMPlatformIPXAddress *const addr_src = NMP_OBJECT_CAST_IPX_ADDRESS(obj_src);
        const NMPlatformIPXAddress       *addr_dst;

        addr_dst = NMP_OBJECT_CAST_IPX_ADDRESS(
            nm_dedup_multi_entry_get_obj(nm_l3_config_data_lookup_obj(self, obj_src)));
        if (!addr_dst)
            continue;

        if (IS_IPv4) {
            NMPlatformIPXRoute       r_stack;
            const NMPlatformIPRoute *r;

            if (addr_dst->a4.a_acd_not_ready)
                continue;

            r = (NMPlatformIPRoute *) nm_platform_ip4_address_generate_device_route(&addr_src->a4,
                                                                                    self->ifindex,
                                                                                    route_table,
                                                                                    route_metric,
                                                                                    force_commit,
                                                                                    &r_stack.r4);
            if (r)
                nm_l3_config_data_add_route(self, addr_family, NULL, r);
        } else {
            const gboolean has_peer = !IN6_IS_ADDR_UNSPECIFIED(&addr_src->a6.peer_address);
            int            routes_i;

            if (addr_src->ax.plen == 0)
                continue;

            if (NM_FLAGS_HAS(addr_src->a6.n_ifa_flags, IFA_F_NOPREFIXROUTE))
                continue;

            /* If we have an IPv6 peer, we add two /128 routes
             * (unless, both addresses are identical). */
            for (routes_i = 0; routes_i < 2; routes_i++) {
                struct in6_addr        a6_stack;
                const struct in6_addr *a6;
                guint8                 plen;

                if (routes_i == 1 && has_peer
                    && IN6_ARE_ADDR_EQUAL(&addr_src->a6.address, &addr_src->a6.peer_address))
                    break;

                if (has_peer) {
                    if (routes_i == 0)
                        a6 = &addr_src->a6.address;
                    else
                        a6 = &addr_src->a6.peer_address;
                    plen = 128;
                } else {
                    a6   = nm_utils_ip6_address_clear_host_address(&a6_stack,
                                                                 &addr_src->a6.address,
                                                                 addr_src->a6.plen);
                    plen = addr_src->a6.plen;
                }

                rx.r6 = (NMPlatformIP6Route){
                    .ifindex        = self->ifindex,
                    .rt_source      = NM_IP_CONFIG_SOURCE_KERNEL,
                    .table_coerced  = nm_platform_route_table_coerce(route_table),
                    .metric         = route_metric,
                    .network        = *a6,
                    .plen           = plen,
                    .r_force_commit = force_commit,
                };

                nm_platform_ip_route_normalize(addr_family, &rx.rx);
                nm_l3_config_data_add_route(self, addr_family, NULL, &rx.rx);
            }
        }
    }
}

/*****************************************************************************/

static void
_init_from_connection_ip(NML3ConfigData *self, int addr_family, NMConnection *connection)
{
    const int          IS_IPv4 = NM_IS_IPv4(addr_family);
    NMSettingIPConfig *s_ip;
    gboolean           never_default;
    guint              naddresses;
    guint              nroutes;
    guint              nnameservers;
    guint              nsearches;
    const char        *gateway_str;
    NMIPAddr           gateway_bin;
    guint              i;
    int                idx;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);
    nm_assert(!connection || NM_IS_CONNECTION(connection));

    if (!connection)
        return;

    s_ip = nm_connection_get_setting_ip_config(connection, addr_family);
    if (!s_ip)
        return;

    never_default = nm_setting_ip_config_get_never_default(s_ip);

    nm_l3_config_data_set_never_default(self, addr_family, !!never_default);

    if (!never_default && (gateway_str = nm_setting_ip_config_get_gateway(s_ip))
        && inet_pton(addr_family, gateway_str, &gateway_bin) == 1
        && !nm_ip_addr_is_null(addr_family, &gateway_bin)) {
        NMPlatformIPXRoute r;

        if (IS_IPv4) {
            r.r4 = (NMPlatformIP4Route){
                .rt_source  = NM_IP_CONFIG_SOURCE_USER,
                .gateway    = gateway_bin.addr4,
                .table_any  = TRUE,
                .metric_any = TRUE,
            };
        } else {
            r.r6 = (NMPlatformIP6Route){
                .rt_source  = NM_IP_CONFIG_SOURCE_USER,
                .gateway    = gateway_bin.addr6,
                .table_any  = TRUE,
                .metric_any = TRUE,
            };
        }

        nm_l3_config_data_add_route(self, addr_family, NULL, &r.rx);
    }

    naddresses = nm_setting_ip_config_get_num_addresses(s_ip);
    for (i = 0; i < naddresses; i++) {
        NMIPAddress         *s_addr = nm_setting_ip_config_get_address(s_ip, i);
        NMPlatformIPXAddress a;
        NMIPAddr             addr_bin;
        GVariant            *label;

        nm_assert(nm_ip_address_get_family(s_addr) == addr_family);

        nm_ip_address_get_address_binary(s_addr, &addr_bin);

        if (IS_IPv4) {
            a.a4 = (NMPlatformIP4Address){
                .address      = addr_bin.addr4,
                .peer_address = addr_bin.addr4,
                .plen         = nm_ip_address_get_prefix(s_addr),
                .lifetime     = NM_PLATFORM_LIFETIME_PERMANENT,
                .preferred    = NM_PLATFORM_LIFETIME_PERMANENT,
                .addr_source  = NM_IP_CONFIG_SOURCE_USER,
            };
            label = nm_ip_address_get_attribute(s_addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
            if (label)
                g_strlcpy(a.a4.label, g_variant_get_string(label, NULL), sizeof(a.a4.label));

            nm_assert(a.a4.plen <= 32);
        } else {
            a.a6 = (NMPlatformIP6Address){
                .address     = addr_bin.addr6,
                .plen        = nm_ip_address_get_prefix(s_addr),
                .lifetime    = NM_PLATFORM_LIFETIME_PERMANENT,
                .preferred   = NM_PLATFORM_LIFETIME_PERMANENT,
                .addr_source = NM_IP_CONFIG_SOURCE_USER,
            };

            nm_assert(a.a6.plen <= 128);
        }

        nm_l3_config_data_add_address(self, addr_family, NULL, &a.ax);
    }

    nroutes = nm_setting_ip_config_get_num_routes(s_ip);
    for (i = 0; i < nroutes; i++) {
        NMIPRoute         *s_route = nm_setting_ip_config_get_route(s_ip, i);
        NMPlatformIPXRoute r;
        NMIPAddr           network_bin;
        NMIPAddr           next_hop_bin;
        gint64             metric64;
        guint32            metric;
        gboolean           metric_any;
        guint              plen;

        nm_assert(nm_ip_route_get_family(s_route) == addr_family);

        nm_ip_route_get_dest_binary(s_route, &network_bin);
        nm_ip_route_get_next_hop_binary(s_route, &next_hop_bin);

        metric64 = nm_ip_route_get_metric(s_route);
        if (metric64 < 0) {
            metric_any = TRUE;
            metric     = 0;
        } else {
            metric_any = FALSE;
            metric     = metric64;
            metric     = nm_utils_ip_route_metric_normalize(addr_family, metric);
        }

        plen = nm_ip_route_get_prefix(s_route);

        nm_utils_ipx_address_clear_host_address(addr_family, &network_bin, &network_bin, plen);

        if (IS_IPv4) {
            r.r4 = (NMPlatformIP4Route){
                .network    = network_bin.addr4,
                .plen       = nm_ip_route_get_prefix(s_route),
                .gateway    = next_hop_bin.addr4,
                .metric_any = metric_any,
                .metric     = metric,
                .rt_source  = NM_IP_CONFIG_SOURCE_USER,
            };
            nm_assert(r.r4.plen <= 32);
        } else {
            r.r6 = (NMPlatformIP6Route){
                .network    = network_bin.addr6,
                .plen       = nm_ip_route_get_prefix(s_route),
                .gateway    = next_hop_bin.addr6,
                .metric_any = metric_any,
                .metric     = metric,
                .rt_source  = NM_IP_CONFIG_SOURCE_USER,
            };
            nm_assert(r.r6.plen <= 128);
        }

        nm_utils_ip_route_attribute_to_platform(addr_family, s_route, &r.rx, -1);

        nm_l3_config_data_add_route(self, addr_family, NULL, &r.rx);
    }

    nnameservers = nm_setting_ip_config_get_num_dns(s_ip);
    for (i = 0; i < nnameservers; i++) {
        const char *s;
        NMIPAddr    ip;

        s = nm_setting_ip_config_get_dns(s_ip, i);
        if (!nm_utils_parse_inaddr_bin(addr_family, s, NULL, &ip))
            continue;
        nm_l3_config_data_add_nameserver(self, addr_family, &ip);
    }

    nsearches = nm_setting_ip_config_get_num_dns_searches(s_ip);
    for (i = 0; i < nsearches; i++) {
        nm_l3_config_data_add_search(self,
                                     addr_family,
                                     nm_setting_ip_config_get_dns_search(s_ip, i));
    }

    idx = 0;
    while ((idx = nm_setting_ip_config_next_valid_dns_option(s_ip, idx)) >= 0) {
        nm_l3_config_data_add_dns_option(self,
                                         addr_family,
                                         nm_setting_ip_config_get_dns_option(s_ip, idx));
        idx++;
    }

    nm_l3_config_data_set_dns_priority(self,
                                       addr_family,
                                       nm_setting_ip_config_get_dns_priority(s_ip));

    if (!IS_IPv4) {
        nm_l3_config_data_set_ip6_privacy(
            self,
            nm_setting_ip6_config_get_ip6_privacy(NM_SETTING_IP6_CONFIG(s_ip)));
    }
}

NML3ConfigData *
nm_l3_config_data_new_from_connection(NMDedupMultiIndex *multi_idx,
                                      int                ifindex,
                                      NMConnection      *connection)
{
    NML3ConfigData *self;
    NMSettingProxy *s_proxy;

    self = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_USER);

    _init_from_connection_ip(self, AF_INET, connection);
    _init_from_connection_ip(self, AF_INET6, connection);

    s_proxy = _nm_connection_get_setting(connection, NM_TYPE_SETTING_PROXY);
    if (s_proxy) {
        switch (nm_setting_proxy_get_method(s_proxy)) {
        case NM_SETTING_PROXY_METHOD_NONE:
            self->proxy_method = NM_PROXY_CONFIG_METHOD_NONE;
            break;
        case NM_SETTING_PROXY_METHOD_AUTO:
            self->proxy_method     = NM_PROXY_CONFIG_METHOD_AUTO;
            self->proxy_pac_url    = nm_ref_string_new(nm_setting_proxy_get_pac_url(s_proxy));
            self->proxy_pac_script = nm_ref_string_new(nm_setting_proxy_get_pac_script(s_proxy));
            break;
        }
        self->proxy_browser_only = (!!nm_setting_proxy_get_browser_only(s_proxy));
    }

    return self;
}

static int
sort_captured_addresses_4(const CList *lst_a, const CList *lst_b, gconstpointer user_data)
{
    const NMPlatformIP4Address *addr_a =
        NMP_OBJECT_CAST_IP4_ADDRESS(c_list_entry(lst_a, NMDedupMultiEntry, lst_entries)->obj);
    const NMPlatformIP4Address *addr_b =
        NMP_OBJECT_CAST_IP4_ADDRESS(c_list_entry(lst_b, NMDedupMultiEntry, lst_entries)->obj);

    nm_assert(addr_a);
    nm_assert(addr_b);

    /* Primary addresses first */
    return NM_FLAGS_HAS(addr_a->n_ifa_flags, IFA_F_SECONDARY)
           - NM_FLAGS_HAS(addr_b->n_ifa_flags, IFA_F_SECONDARY);
}

static int
sort_captured_addresses_6(const CList *lst_a, const CList *lst_b, gconstpointer user_data)
{
    NMSettingIP6ConfigPrivacy   ipv6_privacy_rfc4941 = GPOINTER_TO_INT(user_data);
    const NMPlatformIP6Address *addr_a =
        NMP_OBJECT_CAST_IP6_ADDRESS(c_list_entry(lst_a, NMDedupMultiEntry, lst_entries)->obj);
    const NMPlatformIP6Address *addr_b =
        NMP_OBJECT_CAST_IP6_ADDRESS(c_list_entry(lst_b, NMDedupMultiEntry, lst_entries)->obj);

    return nm_platform_ip6_address_pretty_sort_cmp(
        addr_a,
        addr_b,
        ipv6_privacy_rfc4941 == NM_SETTING_IP6_CONFIG_PRIVACY_PREFER_TEMP_ADDR);
}

static void
_init_from_platform(NML3ConfigData           *self,
                    int                       addr_family,
                    NMPlatform               *platform,
                    NMSettingIP6ConfigPrivacy ipv6_privacy_rfc4941)
{
    const int                    IS_IPv4 = NM_IS_IPv4(addr_family);
    const NMDedupMultiHeadEntry *head_entry;
    const NMPObject             *plobj = NULL;
    NMDedupMultiIter             iter;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert_addr_family(addr_family);

    head_entry = nm_platform_lookup_object(platform,
                                           IS_IPv4 ? NMP_OBJECT_TYPE_IP4_ADDRESS
                                                   : NMP_OBJECT_TYPE_IP6_ADDRESS,
                                           self->ifindex);
    if (head_entry) {
        if (IS_IPv4)
            self->has_routes_with_type_local_4_set = FALSE;
        else
            self->has_routes_with_type_local_6_set = FALSE;
        nmp_cache_iter_for_each (&iter, head_entry, &plobj) {
            if (!_l3_config_data_add_obj(self->multi_idx,
                                         &self->idx_addresses_x[IS_IPv4],
                                         self->ifindex,
                                         plobj,
                                         NULL,
                                         NM_L3_CONFIG_ADD_FLAGS_APPEND_FORCE,
                                         NULL,
                                         NULL))
                nm_assert_not_reached();
        }
        head_entry = nm_l3_config_data_lookup_addresses(self, addr_family);
        nm_assert(head_entry);
        nm_dedup_multi_head_entry_sort(head_entry,
                                       IS_IPv4 ? sort_captured_addresses_4
                                               : sort_captured_addresses_6,
                                       GINT_TO_POINTER(ipv6_privacy_rfc4941));
    }

    head_entry =
        nm_platform_lookup_object(platform,
                                  IS_IPv4 ? NMP_OBJECT_TYPE_IP4_ROUTE : NMP_OBJECT_TYPE_IP6_ROUTE,
                                  self->ifindex);
    nmp_cache_iter_for_each (&iter, head_entry, &plobj)
        nm_l3_config_data_add_route(self, addr_family, plobj, NULL);
}

NML3ConfigData *
nm_l3_config_data_new_from_platform(NMDedupMultiIndex        *multi_idx,
                                    int                       ifindex,
                                    NMPlatform               *platform,
                                    NMSettingIP6ConfigPrivacy ipv6_privacy_rfc4941)
{
    NML3ConfigData *self;

    nm_assert(NM_IS_PLATFORM(platform));
    nm_assert(ifindex > 0);

    /* Slaves have no IP configuration */
    if (nm_platform_link_get_master(platform, ifindex) > 0)
        return NULL;

    self = nm_l3_config_data_new(multi_idx, ifindex, NM_IP_CONFIG_SOURCE_KERNEL);

    _init_from_platform(self, AF_INET, platform, ipv6_privacy_rfc4941);
    _init_from_platform(self, AF_INET6, platform, ipv6_privacy_rfc4941);

    return self;
}

/*****************************************************************************/

void
nm_l3_config_data_merge(NML3ConfigData       *self,
                        const NML3ConfigData *src,
                        NML3ConfigMergeFlags  merge_flags,
                        const guint32        *default_route_table_x /* length 2, for IS_IPv4 */,
                        const guint32        *default_route_metric_x /* length 2, for IS_IPv4 */,
                        const guint32        *default_route_penalty_x /* length 2, for IS_IPv4 */,
                        const int            *default_dns_priority_x /* length 2, for IS_IPv4 */,
                        NML3ConfigMergeHookAddObj hook_add_obj,
                        gpointer                  hook_user_data)
{
    static const guint32 x_default_route_metric_x[2]  = {NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP6,
                                                        NM_PLATFORM_ROUTE_METRIC_DEFAULT_IP4};
    static const guint32 x_default_route_penalty_x[2] = {0, 0};
    static const int     x_default_dns_priority_x[2]  = {NM_DNS_PRIORITY_DEFAULT_NORMAL,
                                                    NM_DNS_PRIORITY_DEFAULT_NORMAL};
    guint32              default_route_table_coerced_x[2];
    NMDedupMultiIter     iter;
    const NMPObject     *obj;
    int                  IS_IPv4;

    nm_assert(_NM_IS_L3_CONFIG_DATA(self, FALSE));
    nm_assert(_NM_IS_L3_CONFIG_DATA(src, TRUE));

    if (default_route_table_x) {
        default_route_table_coerced_x[0] = nm_platform_route_table_coerce(default_route_table_x[0]);
        default_route_table_coerced_x[1] = nm_platform_route_table_coerce(default_route_table_x[1]);
    } else {
        default_route_table_coerced_x[0] = nm_platform_route_table_coerce(RT_TABLE_MAIN);
        default_route_table_coerced_x[1] = nm_platform_route_table_coerce(RT_TABLE_MAIN);
    }
    nm_assert(nm_platform_route_table_uncoerce(default_route_table_coerced_x[0], FALSE) != 0);
    nm_assert(nm_platform_route_table_uncoerce(default_route_table_coerced_x[1], FALSE) != 0);

    if (!default_route_metric_x)
        default_route_metric_x = x_default_route_metric_x;
    if (!default_route_penalty_x)
        default_route_penalty_x = x_default_route_penalty_x;
    if (!default_dns_priority_x)
        default_dns_priority_x = x_default_dns_priority_x;

    nm_assert(default_route_metric_x[0] != 0); /* IPv6 route metric cannot be zero. */

    nm_assert(!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_CLONE)
              || nm_utils_is_power_of_two(merge_flags));

    for (IS_IPv4 = 1; IS_IPv4 >= 0; IS_IPv4--) {
        const int                addr_family = IS_IPv4 ? AF_INET : AF_INET6;
        const NML3ConfigDatFlags has_dns_priority_flag =
            NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY(IS_IPv4);

        nm_l3_config_data_iter_obj_for_each (&iter,
                                             src,
                                             &obj,
                                             NMP_OBJECT_TYPE_IP_ADDRESS(IS_IPv4)) {
            const NMPlatformIPAddress *a_src = NMP_OBJECT_CAST_IP_ADDRESS(obj);
            NMPlatformIPXAddress       a;
            NML3ConfigMergeHookResult  hook_result = {
                 .ip4acd_not_ready   = NM_OPTION_BOOL_DEFAULT,
                 .assume_config_once = NM_OPTION_BOOL_DEFAULT,
                 .force_commit       = NM_OPTION_BOOL_DEFAULT,
            };

#define _ensure_a()                                       \
    G_STMT_START                                          \
    {                                                     \
        if (a_src != &a.ax) {                             \
            if (IS_IPv4)                                  \
                a.a4 = *NMP_OBJECT_CAST_IP4_ADDRESS(obj); \
            else                                          \
                a.a6 = *NMP_OBJECT_CAST_IP6_ADDRESS(obj); \
            a_src = &a.ax;                                \
        }                                                 \
    }                                                     \
    G_STMT_END

            if (hook_add_obj && !hook_add_obj(src, obj, &hook_result, hook_user_data))
                continue;

            nm_assert(IS_IPv4 || hook_result.ip4acd_not_ready == NM_OPTION_BOOL_DEFAULT);

            if (a_src->ifindex != self->ifindex) {
                _ensure_a();
                a.ax.ifindex = self->ifindex;
            }

            if (hook_result.ip4acd_not_ready != NM_OPTION_BOOL_DEFAULT && IS_IPv4
                && (!!hook_result.ip4acd_not_ready)
                       != ((const NMPlatformIP4Address *) a_src)->a_acd_not_ready) {
                _ensure_a();
                a.a4.a_acd_not_ready = (!!hook_result.ip4acd_not_ready);
            }

            if (hook_result.assume_config_once != NM_OPTION_BOOL_DEFAULT
                && (!!hook_result.assume_config_once) != a_src->a_assume_config_once) {
                _ensure_a();
                a.ax.a_assume_config_once = (!!hook_result.assume_config_once);
            }

            if (hook_result.force_commit != NM_OPTION_BOOL_DEFAULT
                && (!!hook_result.force_commit) != a_src->a_force_commit) {
                _ensure_a();
                a.ax.a_force_commit = (!!hook_result.force_commit);
            }

            nm_l3_config_data_add_address_full(self,
                                               addr_family,
                                               a_src == &a.ax ? NULL : obj,
                                               a_src == &a.ax ? a_src : NULL,
                                               NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE,
                                               NULL);
        }

#undef _ensure_a

        if (!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES)) {
            nm_l3_config_data_iter_obj_for_each (&iter,
                                                 src,
                                                 &obj,
                                                 NMP_OBJECT_TYPE_IP_ROUTE(IS_IPv4)) {
                const NMPlatformIPRoute  *r_src = NMP_OBJECT_CAST_IP_ROUTE(obj);
                NMPlatformIPXRoute        r;
                NML3ConfigMergeHookResult hook_result = {
                    .ip4acd_not_ready   = NM_OPTION_BOOL_DEFAULT,
                    .assume_config_once = NM_OPTION_BOOL_DEFAULT,
                    .force_commit       = NM_OPTION_BOOL_DEFAULT,
                };

#define _ensure_r()                                     \
    G_STMT_START                                        \
    {                                                   \
        if (r_src != &r.rx) {                           \
            if (IS_IPv4)                                \
                r.r4 = *NMP_OBJECT_CAST_IP4_ROUTE(obj); \
            else                                        \
                r.r6 = *NMP_OBJECT_CAST_IP6_ROUTE(obj); \
            r_src = &r.rx;                              \
        }                                               \
    }                                                   \
    G_STMT_END

                if (hook_add_obj && !hook_add_obj(src, obj, &hook_result, hook_user_data))
                    continue;

                nm_assert(hook_result.ip4acd_not_ready == NM_OPTION_BOOL_DEFAULT);

                if (r_src->ifindex != self->ifindex) {
                    _ensure_r();
                    r.rx.ifindex = self->ifindex;
                }

                if (hook_result.assume_config_once != NM_OPTION_BOOL_DEFAULT
                    && (!!hook_result.assume_config_once) != r_src->r_assume_config_once) {
                    _ensure_r();
                    r.rx.r_assume_config_once = (!!hook_result.assume_config_once);
                }

                if (hook_result.force_commit != NM_OPTION_BOOL_DEFAULT
                    && (!!hook_result.force_commit) != r_src->r_force_commit) {
                    _ensure_r();
                    r.rx.r_force_commit = (!!hook_result.force_commit);
                }

                if (!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_CLONE)) {
                    if (r_src->table_any) {
                        _ensure_r();
                        r.rx.table_any     = FALSE;
                        r.rx.table_coerced = default_route_table_coerced_x[IS_IPv4];
                    }

                    if (r_src->metric_any) {
                        _ensure_r();
                        r.rx.metric_any = FALSE;
                        r.rx.metric =
                            nm_add_clamped_u32(r.rx.metric, default_route_metric_x[IS_IPv4]);
                    }

                    if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT(r_src)) {
                        if (NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES)
                            && !NM_FLAGS_HAS(src->flags,
                                             NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES))
                            continue;
                        if (default_route_penalty_x && default_route_penalty_x[IS_IPv4] > 0) {
                            _ensure_r();
                            r.rx.metric =
                                nm_utils_ip_route_metric_penalize(r.rx.metric,
                                                                  default_route_penalty_x[IS_IPv4]);
                        }
                    }
                }

                nm_l3_config_data_add_route_full(self,
                                                 addr_family,
                                                 r_src == &r.rx ? NULL : obj,
                                                 r_src == &r.rx ? r_src : NULL,
                                                 NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE,
                                                 NULL,
                                                 NULL);
            }

#undef _ensure_r
        }

        if (!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_DNS))
            _garray_inaddr_merge(&self->nameservers_x[IS_IPv4],
                                 src->nameservers_x[IS_IPv4],
                                 addr_family);

        if (!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_DNS))
            _strv_ptrarray_merge(&self->domains_x[IS_IPv4], src->domains_x[IS_IPv4]);

        if (!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_DNS))
            _strv_ptrarray_merge(&self->searches_x[IS_IPv4], src->searches_x[IS_IPv4]);

        if (!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_DNS))
            _strv_ptrarray_merge(&self->dns_options_x[IS_IPv4], src->dns_options_x[IS_IPv4]);

        if (!NM_FLAGS_ANY(self->flags, has_dns_priority_flag)
            && NM_FLAGS_ANY(src->flags, has_dns_priority_flag)) {
            int p = src->dns_priority_x[IS_IPv4];

            if (p == 0 && !NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_CLONE))
                p = default_dns_priority_x[IS_IPv4];

            self->dns_priority_x[IS_IPv4] = p;
            self->flags |= has_dns_priority_flag;
        }

        if (self->route_table_sync_x[IS_IPv4] == NM_IP_ROUTE_TABLE_SYNC_MODE_NONE)
            self->route_table_sync_x[IS_IPv4] = src->route_table_sync_x[IS_IPv4];

        if (self->never_default_x[IS_IPv4] == NM_OPTION_BOOL_DEFAULT)
            self->never_default_x[IS_IPv4] = src->never_default_x[IS_IPv4];
    }

    if (!NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_NO_DNS)) {
        _garray_inaddr_merge(&self->wins, src->wins, AF_INET);
        _garray_inaddr_merge(&self->nis_servers, src->nis_servers, AF_INET);

        if (!self->nis_domain)
            self->nis_domain = nm_ref_string_ref(src->nis_domain);
    }

    if (self->mdns == NM_SETTING_CONNECTION_MDNS_DEFAULT)
        self->mdns = src->mdns;

    if (self->llmnr == NM_SETTING_CONNECTION_LLMNR_DEFAULT)
        self->llmnr = src->llmnr;

    if (self->dns_over_tls == NM_SETTING_CONNECTION_DNS_OVER_TLS_DEFAULT)
        self->dns_over_tls = src->dns_over_tls;

    if (self->ip6_token.id == 0)
        self->ip6_token.id = src->ip6_token.id;

    self->metered = NM_MAX((NMTernary) self->metered, (NMTernary) src->metered);

    if (self->proxy_method == NM_PROXY_CONFIG_METHOD_UNKNOWN)
        self->proxy_method = src->proxy_method;

    if (self->proxy_browser_only == NM_TERNARY_DEFAULT)
        self->proxy_browser_only = src->proxy_browser_only;

    if (!self->proxy_pac_url)
        self->proxy_pac_url = nm_ref_string_ref(src->proxy_pac_url);

    if (!self->proxy_pac_script)
        self->proxy_pac_script = nm_ref_string_ref(src->proxy_pac_script);

    if (self->ip6_privacy == NM_SETTING_IP6_CONFIG_PRIVACY_UNKNOWN)
        self->ip6_privacy = src->ip6_privacy;

    if (!self->ndisc_hop_limit_set && src->ndisc_hop_limit_set) {
        self->ndisc_hop_limit_set = TRUE;
        self->ndisc_hop_limit_val = src->ndisc_hop_limit_val;
    }

    if (!self->ndisc_reachable_time_msec_set && src->ndisc_reachable_time_msec_set) {
        self->ndisc_reachable_time_msec_set = TRUE;
        self->ndisc_reachable_time_msec_val = src->ndisc_reachable_time_msec_val;
    }

    if (!self->ndisc_retrans_timer_msec_set && src->ndisc_retrans_timer_msec_set) {
        self->ndisc_retrans_timer_msec_set = TRUE;
        self->ndisc_retrans_timer_msec_val = src->ndisc_retrans_timer_msec_val;
    }

    if (self->mtu == 0u)
        self->mtu = src->mtu;

    if (self->ip6_mtu == 0u)
        self->ip6_mtu = src->ip6_mtu;

    if (NM_FLAGS_HAS(merge_flags, NM_L3_CONFIG_MERGE_FLAGS_CLONE)) {
        _nm_unused nm_auto_unref_dhcplease NMDhcpLease *dhcp_lease_6 =
            g_steal_pointer(&self->dhcp_lease_x[0]);
        _nm_unused nm_auto_unref_dhcplease NMDhcpLease *dhcp_lease_4 =
            g_steal_pointer(&self->dhcp_lease_x[1]);

        self->source          = src->source;
        self->dhcp_lease_x[0] = nm_dhcp_lease_ref(self->dhcp_lease_x[0]);
        self->dhcp_lease_x[1] = nm_dhcp_lease_ref(self->dhcp_lease_x[1]);
    }
}

NML3ConfigData *
nm_l3_config_data_new_clone(const NML3ConfigData *src, int ifindex)
{
    NML3ConfigData *self;

    nm_assert(_NM_IS_L3_CONFIG_DATA(src, TRUE));

    /* pass 0, to use the original ifindex. You can also use this function to
     * copy the configuration for a different ifindex. */
    nm_assert(ifindex >= 0);
    if (ifindex <= 0)
        ifindex = src->ifindex;

    self = nm_l3_config_data_new(src->multi_idx, ifindex, src->source);
    nm_l3_config_data_merge(self,
                            src,
                            NM_L3_CONFIG_MERGE_FLAGS_CLONE,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL,
                            NULL);

    nm_assert(nm_l3_config_data_cmp_full(src,
                                         self,
                                         src->ifindex == ifindex
                                             ? NM_L3_CONFIG_CMP_FLAGS_ALL
                                             : NM_L3_CONFIG_CMP_FLAGS_ALL
                                                   & ~(NM_L3_CONFIG_CMP_FLAGS_IFINDEX))
              == 0);
    nm_assert(nm_l3_config_data_get_ifindex(self) == ifindex);

    return self;
}
