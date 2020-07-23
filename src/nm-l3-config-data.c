// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-l3-config-data.h"

#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "platform/nmp-object.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

typedef struct {
	NMDedupMultiIdxType parent;
	NMPObjectType obj_type;
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

	union {
		struct {
			int dns_priority_6;
			int dns_priority_4;
		};
		int dns_priority_x[2];
	};

	NMSettingConnectionMdns mdns;
	NMSettingConnectionLlmnr llmnr;

	int ref_count;

	bool is_sealed:1;
};

/*****************************************************************************/

static gboolean
_route_valid_4 (const NMPlatformIP4Route *r)
{
	return    r
	       && r->plen <= 32
	       && r->network == nm_utils_ip4_address_clear_host_address (r->network, r->plen);
}

static gboolean
_route_valid_6 (const NMPlatformIP6Route *r)
{
	struct in6_addr n;

	return    r
	       && r->plen <= 128
	       && (memcmp (&r->network,
	                   nm_utils_ip6_address_clear_host_address (&n, &r->network, r->plen),
	                   sizeof (n)) == 0);
}

static gboolean
_route_valid (int addr_family, gconstpointer r)
{
	nm_assert_addr_family (addr_family);

	return   addr_family == AF_INET
	       ? _route_valid_4 (r)
	       : _route_valid_6 (r);
}

static gboolean
NM_IS_L3_CONFIG_DATA (const NML3ConfigData *self, gboolean allow_sealed)
{
	return    self
	       && self->ref_count > 0
	       && (   allow_sealed
	           || !self->is_sealed);
}

static GArray *
_garray_ensure_for_addrbin (GArray **p_arr,
                            int addr_family)
{
	nm_assert (p_arr);
	nm_assert_addr_family (addr_family);

	if (G_UNLIKELY (!*p_arr)) {
		*p_arr = g_array_new (FALSE,
		                      FALSE,
		                      nm_utils_addr_family_to_size (addr_family));
	}
	return *p_arr;
}

static void
_idx_obj_id_hash_update (const NMDedupMultiIdxType *idx_type,
                         const NMDedupMultiObj *obj,
                         NMHashState *h)
{
	nmp_object_id_hash_update ((NMPObject *) obj, h);
}

static gboolean
_idx_obj_id_equal (const NMDedupMultiIdxType *idx_type,
                   const NMDedupMultiObj *obj_a,
                   const NMDedupMultiObj *obj_b)
{
	return nmp_object_id_equal ((NMPObject *) obj_a, (NMPObject *) obj_b);
}

static void
_idx_type_init (DedupMultiIdxType *idx_type,
                NMPObjectType obj_type)
{
	static const NMDedupMultiIdxTypeClass idx_type_class = {
		.idx_obj_id_hash_update = _idx_obj_id_hash_update,
		.idx_obj_id_equal       = _idx_obj_id_equal,
	};

	nm_dedup_multi_idx_type_init (&idx_type->parent,
	                              &idx_type_class);
	idx_type->obj_type = obj_type;
}

NML3ConfigData *
nm_l3_config_data_new (NMDedupMultiIndex *multi_idx)
{
	NML3ConfigData *self;

	nm_assert (multi_idx);

	self = g_slice_new (NML3ConfigData);
	*self = (NML3ConfigData) {
		.ref_count = 1,
		.multi_idx = nm_dedup_multi_index_ref (multi_idx),
		.mdns      = NM_SETTING_CONNECTION_MDNS_DEFAULT,
		.llmnr     = NM_SETTING_CONNECTION_LLMNR_DEFAULT,
	};

	_idx_type_init (&self->idx_addresses_4, NMP_OBJECT_TYPE_IP4_ADDRESS);
	_idx_type_init (&self->idx_addresses_6, NMP_OBJECT_TYPE_IP4_ADDRESS);
	_idx_type_init (&self->idx_routes_4, NMP_OBJECT_TYPE_IP4_ROUTE);
	_idx_type_init (&self->idx_routes_6, NMP_OBJECT_TYPE_IP6_ROUTE);

	return self;
}

NML3ConfigData *
nm_l3_config_data_ref (NML3ConfigData *self)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, TRUE));
	self->ref_count++;
	return self;
}

NML3ConfigData *
nm_l3_config_data_ref_and_seal (NML3ConfigData *self)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, TRUE));
	self->is_sealed = TRUE;
	self->ref_count++;
	return self;
}

NML3ConfigData *
nm_l3_config_data_seal (NML3ConfigData *self)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, TRUE));
	self->is_sealed = TRUE;
	return self;
}

gboolean
nm_l3_config_data_is_sealed (NML3ConfigData *self)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, TRUE));
	return self->is_sealed;
}

void
nm_l3_config_data_unref (NML3ConfigData *self)
{
	if (!self)
		return;

	nm_assert (NM_IS_L3_CONFIG_DATA (self, TRUE));
	if (--self->ref_count > 0)
		return;

	nm_dedup_multi_index_remove_idx (self->multi_idx, &self->idx_addresses_4.parent);
	nm_dedup_multi_index_remove_idx (self->multi_idx, &self->idx_addresses_6.parent);
	nm_dedup_multi_index_remove_idx (self->multi_idx, &self->idx_routes_4.parent);
	nm_dedup_multi_index_remove_idx (self->multi_idx, &self->idx_routes_6.parent);

	nmp_object_unref (self->best_default_route_4);
	nmp_object_unref (self->best_default_route_6);

	nm_clear_pointer (&self->nameservers_4, g_array_unref);
	nm_clear_pointer (&self->nameservers_6, g_array_unref);

	nm_clear_pointer (&self->domains_4, g_ptr_array_unref);
	nm_clear_pointer (&self->domains_6, g_ptr_array_unref);

	nm_clear_pointer (&self->searches_4, g_ptr_array_unref);
	nm_clear_pointer (&self->searches_6, g_ptr_array_unref);

	nm_clear_pointer (&self->dns_options_4, g_ptr_array_unref);
	nm_clear_pointer (&self->dns_options_6, g_ptr_array_unref);

	nm_dedup_multi_index_unref (self->multi_idx);

	nm_g_slice_free (self);
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *
nm_l3_config_data_lookup_addresses (const NML3ConfigData *self,
                                    int addr_family)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, TRUE));
	nm_assert_addr_family (addr_family);

	return nm_dedup_multi_index_lookup_head (self->multi_idx,
	                                         &self->idx_addresses_x[NM_IS_IPv4 (addr_family)].parent,
	                                         NULL);
}

const NMDedupMultiHeadEntry *
nm_l3_config_data_lookup_routes (const NML3ConfigData *self,
                                 int addr_family)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, TRUE));
	nm_assert_addr_family (addr_family);

	return nm_dedup_multi_index_lookup_head (self->multi_idx,
	                                         &self->idx_routes_x[NM_IS_IPv4 (addr_family)].parent,
	                                         NULL);
}

/*****************************************************************************/

static gboolean
_l3_config_data_add_obj (NMDedupMultiIndex *multi_idx,
                         DedupMultiIdxType *idx_type,
                         int ifindex,
                         const NMPObject *obj_new,
                         const NMPlatformObject *pl_new,
                         gboolean merge,
                         gboolean append_force,
                         const NMPObject **out_obj_old /* returns a reference! */,
                         const NMPObject **out_obj_new /* does not return a reference */)
{
	NMPObject obj_new_stackinit;
	const NMDedupMultiEntry *entry_old;
	const NMDedupMultiEntry *entry_new;

	nm_assert (multi_idx);
	nm_assert (idx_type);
	nm_assert (NM_IN_SET (idx_type->obj_type, NMP_OBJECT_TYPE_IP4_ADDRESS,
	                                          NMP_OBJECT_TYPE_IP4_ROUTE,
	                                          NMP_OBJECT_TYPE_IP6_ADDRESS,
	                                          NMP_OBJECT_TYPE_IP6_ROUTE));
	nm_assert (ifindex > 0);

	/* we go through extra lengths to accept a full obj_new object. That one,
	 * can be reused by increasing the ref-count. */
	if (!obj_new) {
		nm_assert (pl_new);
		obj_new = nmp_object_stackinit (&obj_new_stackinit, idx_type->obj_type, pl_new);
		NMP_OBJECT_CAST_OBJ_WITH_IFINDEX (&obj_new_stackinit)->ifindex = ifindex;
	} else {
		nm_assert (!pl_new);
		nm_assert (NMP_OBJECT_GET_TYPE (obj_new) == idx_type->obj_type);
		if (NMP_OBJECT_CAST_OBJ_WITH_IFINDEX (obj_new)->ifindex != ifindex) {
			obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
			NMP_OBJECT_CAST_OBJ_WITH_IFINDEX (&obj_new_stackinit)->ifindex = ifindex;
		}
	}
	nm_assert (NMP_OBJECT_GET_TYPE (obj_new) == idx_type->obj_type);
	nm_assert (nmp_object_is_alive (obj_new));

	entry_old = nm_dedup_multi_index_lookup_obj (multi_idx, &idx_type->parent, obj_new);

	if (entry_old) {
		gboolean modified = FALSE;
		const NMPObject *obj_old = entry_old->obj;

		if (nmp_object_equal (obj_new, obj_old)) {
			nm_dedup_multi_entry_set_dirty (entry_old, FALSE);
			goto append_force_and_out;
		}

		/* if @merge, we merge the new object with the existing one.
		 * Otherwise, we replace it entirely. */
		if (merge) {
			switch (idx_type->obj_type) {
			case NMP_OBJECT_TYPE_IP4_ADDRESS:
			case NMP_OBJECT_TYPE_IP6_ADDRESS:
				/* for addresses that we read from the kernel, we keep the timestamps as defined
				 * by the previous source (item_old). The reason is, that the other source configured the lifetimes
				 * with "what should be" and the kernel values are "what turned out after configuring it".
				 *
				 * For other sources, the longer lifetime wins. */
				if (   (   obj_new->ip_address.addr_source == NM_IP_CONFIG_SOURCE_KERNEL
				        && obj_old->ip_address.addr_source != NM_IP_CONFIG_SOURCE_KERNEL)
				    || nm_platform_ip_address_cmp_expiry (NMP_OBJECT_CAST_IP_ADDRESS (obj_old), NMP_OBJECT_CAST_IP_ADDRESS(obj_new)) > 0) {
					obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
					obj_new_stackinit.ip_address.timestamp = NMP_OBJECT_CAST_IP_ADDRESS (obj_old)->timestamp;
					obj_new_stackinit.ip_address.lifetime  = NMP_OBJECT_CAST_IP_ADDRESS (obj_old)->lifetime;
					obj_new_stackinit.ip_address.preferred = NMP_OBJECT_CAST_IP_ADDRESS (obj_old)->preferred;
					modified = TRUE;
				}

				/* keep the maximum addr_source. */
				if (obj_new->ip_address.addr_source < obj_old->ip_address.addr_source) {
					obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
					obj_new_stackinit.ip_address.addr_source = obj_old->ip_address.addr_source;
					modified = TRUE;
				}
				break;
			case NMP_OBJECT_TYPE_IP4_ROUTE:
			case NMP_OBJECT_TYPE_IP6_ROUTE:
				/* keep the maximum rt_source. */
				if (obj_new->ip_route.rt_source < obj_old->ip_route.rt_source) {
					obj_new = nmp_object_stackinit_obj (&obj_new_stackinit, obj_new);
					obj_new_stackinit.ip_route.rt_source = obj_old->ip_route.rt_source;
					modified = TRUE;
				}
				break;
			default:
				nm_assert_not_reached ();
				break;
			}

			if (   modified
			    && nmp_object_equal (obj_new, obj_old)) {
				nm_dedup_multi_entry_set_dirty (entry_old, FALSE);
				goto append_force_and_out;
			}
		}
	}

	if (!nm_dedup_multi_index_add_full (multi_idx,
	                                    &idx_type->parent,
	                                    obj_new,
	                                      append_force
	                                    ? NM_DEDUP_MULTI_IDX_MODE_APPEND_FORCE
	                                    : NM_DEDUP_MULTI_IDX_MODE_APPEND,
	                                    NULL,
	                                    entry_old ?: NM_DEDUP_MULTI_ENTRY_MISSING,
	                                    NULL,
	                                    &entry_new,
	                                    out_obj_old)) {
		nm_assert_not_reached ();
		NM_SET_OUT (out_obj_new, NULL);
		return FALSE;
	}

	NM_SET_OUT (out_obj_new, entry_new->obj);
	return TRUE;

append_force_and_out:
	NM_SET_OUT (out_obj_old, nmp_object_ref (entry_old->obj));
	NM_SET_OUT (out_obj_new, entry_old->obj);
	if (append_force) {
		if (nm_dedup_multi_entry_reorder (entry_old, NULL, TRUE))
			return TRUE;
	}
	return FALSE;
}

static const NMPObject *
_l3_config_best_default_route_find_better (const NMPObject *obj_cur, const NMPObject *obj_cmp)
{
	nm_assert (   !obj_cur
	           || NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_cur), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE));
	nm_assert (   !obj_cmp
	           || (   !obj_cur
	               && NM_IN_SET (NMP_OBJECT_GET_TYPE (obj_cmp), NMP_OBJECT_TYPE_IP4_ROUTE, NMP_OBJECT_TYPE_IP6_ROUTE))
	           || NMP_OBJECT_GET_TYPE (obj_cur) == NMP_OBJECT_GET_TYPE (obj_cmp));
	nm_assert (   !obj_cur
	           || nmp_object_ip_route_is_best_defaut_route (obj_cur));

	/* assumes that @obj_cur is already the best default route (or NULL). It checks whether
	 * @obj_cmp is also a default route and returns the best of both. */
	if (   obj_cmp
	    && nmp_object_ip_route_is_best_defaut_route (obj_cmp)) {
		guint32 metric_cur, metric_cmp;

		if (!obj_cur)
			return obj_cmp;

		if (obj_cur == obj_cmp)
			return obj_cmp;

		metric_cur = NMP_OBJECT_CAST_IP_ROUTE (obj_cur)->metric;
		metric_cmp = NMP_OBJECT_CAST_IP_ROUTE (obj_cmp)->metric;

		if (metric_cmp < metric_cur)
			return obj_cmp;

		if (metric_cmp == metric_cur) {
			int c;

			/* Routes have the same metric. We still want to deterministically
			 * prefer one or the other. It's important to consistently choose one
			 * or the other, so that the order doesn't matter how routes are added
			 * (and merged). */
			c = nmp_object_cmp (obj_cur, obj_cmp);
			if (c != 0)
				return c < 0 ? obj_cur : obj_cmp;

			/* as last resort, compare pointers. */
			if (((uintptr_t) ((void *) (obj_cmp))) < ((uintptr_t) ((void *) (obj_cur))))
				return obj_cmp;
		}
	}
	return obj_cur;
}

static gboolean
_l3_config_best_default_route_merge (const NMPObject **best_default_route, const NMPObject *new_candidate)
{
	new_candidate = _l3_config_best_default_route_find_better (*best_default_route,
	                                                           new_candidate);
	return nmp_object_ref_set (best_default_route, new_candidate);
}

gboolean
_nm_l3_config_data_add_route (NML3ConfigData *self,
                              int addr_family,
                              int ifindex,
                              const NMPObject *obj_new,
                              const NMPlatformIPRoute *pl_new,
                              const NMPObject **out_obj_new,
                              gboolean *out_changed_best_default_route)
{
	const gboolean IS_IPv4 = NM_IS_IPv4 (addr_family);
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	const NMPObject *obj_new_2;
	gboolean changed = FALSE;
	gboolean changed_best_default_route = FALSE;

	nm_assert_addr_family (addr_family);
	nm_assert (ifindex > 0);
	nm_assert ((!pl_new) != (!obj_new));
	nm_assert (   !pl_new
	           || _route_valid (addr_family, pl_new));
	nm_assert (   !obj_new
	           || (   NMP_OBJECT_GET_ADDR_FAMILY (obj_new) == addr_family
	               && _route_valid (addr_family, NMP_OBJECT_CAST_IP_ROUTE (obj_new))));

	if (_l3_config_data_add_obj (self->multi_idx,
	                               addr_family == AF_INET
	                             ? &self->idx_routes_4
	                             : &self->idx_routes_6,
	                             ifindex,
	                             obj_new,
	                             (const NMPlatformObject *) pl_new,
	                             TRUE,
	                             FALSE,
	                             &obj_old,
	                             &obj_new_2)) {

		if (   self->best_default_route_x[IS_IPv4] == obj_old
		    && obj_old != obj_new_2) {
			changed_best_default_route = TRUE;
			nm_clear_nmp_object (&self->best_default_route_x[IS_IPv4]);
		}

		if (_l3_config_best_default_route_merge (&self->best_default_route_x[IS_IPv4],
		                                         obj_new_2))
			changed_best_default_route = TRUE;

		changed = TRUE;
	}

	NM_SET_OUT (out_obj_new, nmp_object_ref (obj_new_2));
	NM_SET_OUT (out_changed_best_default_route, changed_best_default_route);
	return changed;
}

gboolean
_nm_l3_config_data_add_address (NML3ConfigData *self,
                                int addr_family,
                                int ifindex,
                                const NMPObject *obj_new,
                                const NMPlatformIPAddress *pl_new)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, FALSE));
	nm_assert_addr_family (addr_family);
	nm_assert (ifindex > 0);
	nm_assert ((!pl_new) != (!obj_new));
	nm_assert (   !obj_new
	           || NMP_OBJECT_GET_ADDR_FAMILY (obj_new) == addr_family);

	return _l3_config_data_add_obj (self->multi_idx,
	                                  addr_family == AF_INET
	                                ? &self->idx_addresses_4
	                                : &self->idx_addresses_6,
	                                ifindex,
	                                obj_new,
	                                (const NMPlatformObject *) pl_new,
	                                TRUE,
	                                FALSE,
	                                NULL,
	                                NULL);
}

/*****************************************************************************/

static gboolean
_check_and_add_domain (GPtrArray **p_arr, const char *domain)
{
	gs_free char *copy = NULL;
	gsize len;

	nm_assert (p_arr);
	g_return_val_if_fail (domain, FALSE);

	if (domain[0] == '\0')
		g_return_val_if_reached (FALSE);

	if (domain[0] == '.' || strstr (domain, ".."))
		return FALSE;

	len = strlen (domain);
	if (domain[len - 1] == '.') {
		copy = g_strndup (domain, len - 1);
		domain = copy;
	}

	if (nm_strv_ptrarray_contains (*p_arr, domain))
		return FALSE;

	nm_strv_ptrarray_add_string_take (nm_strv_ptrarray_ensure (p_arr),
	                                     g_steal_pointer (&copy)
	                                  ?: g_strdup (domain));
	return TRUE;
}

gboolean
_nm_l3_config_data_add_domain (NML3ConfigData *self,
                               int addr_family,
                               const char *domain)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, FALSE));
	nm_assert_addr_family (addr_family);

	return _check_and_add_domain (&self->domains_x[NM_IS_IPv4 (addr_family)], domain);
}

gboolean
_nm_l3_config_data_add_search (NML3ConfigData *self,
                               int addr_family,
                               const char *search)
{
	nm_assert (NM_IS_L3_CONFIG_DATA (self, FALSE));
	nm_assert_addr_family (addr_family);

	return _check_and_add_domain (&self->searches_x[NM_IS_IPv4 (addr_family)], search);
}

gboolean
_nm_l3_config_data_add_dns_option (NML3ConfigData *self,
                                   int addr_family,
                                   const char *dns_option)
{
	GPtrArray **p_arr;

	nm_assert (NM_IS_L3_CONFIG_DATA (self, FALSE));
	nm_assert_addr_family (addr_family);

	g_return_val_if_fail (dns_option, FALSE);

	if (!dns_option[0])
		g_return_val_if_reached (FALSE);

	p_arr = &self->dns_options_x[NM_IS_IPv4 (addr_family)];

	if (nm_strv_ptrarray_contains (*p_arr, dns_option))
		return FALSE;

	nm_strv_ptrarray_add_string_dup (nm_strv_ptrarray_ensure (p_arr),
	                                 dns_option);
	return TRUE;
}

gboolean
_nm_l3_config_data_set_dns_priority (NML3ConfigData *self,
                                     int addr_family,
                                     int dns_priority)
{
	int *p_val;

	nm_assert (NM_IS_L3_CONFIG_DATA (self, FALSE));
	nm_assert_addr_family (addr_family);

	p_val = &self->dns_priority_x[NM_IS_IPv4 (addr_family)];
	if (*p_val == dns_priority)
		return FALSE;

	*p_val = dns_priority;
	return TRUE;
}

/*****************************************************************************/

static void
_init_from_connection_ip (NML3ConfigData *self,
                          int addr_family,
                          int ifindex,
                          NMConnection *connection,
                          guint32 route_table,
                          guint32 route_metric)
{
	const gboolean IS_IPv4 = NM_IS_IPv4 (addr_family);
	NMSettingIPConfig *s_ip;
	guint naddresses;
	guint nroutes;
	guint nnameservers;
	guint nsearches;
	const char *gateway_str;
	NMIPAddr gateway_bin;
	guint i;
	int idx;

	nm_assert (NM_IS_L3_CONFIG_DATA (self, FALSE));
	nm_assert (ifindex > 0);
	nm_assert_addr_family (addr_family);
	nm_assert (!connection || NM_IS_CONNECTION (connection));

	if (!connection)
		return;

	s_ip = nm_connection_get_setting_ip_config (connection, addr_family);
	if (!s_ip)
		return;

	if (   !nm_setting_ip_config_get_never_default (s_ip)
	    && (gateway_str = nm_setting_ip_config_get_gateway (s_ip))
	    && inet_pton (addr_family, gateway_str, &gateway_bin) == 1
	    && !nm_ip_addr_is_null (addr_family, &gateway_bin)) {
		NMPlatformIPXRoute r;

		if (IS_IPv4) {
			r.r4 = (NMPlatformIP4Route) {
				.rt_source     = NM_IP_CONFIG_SOURCE_USER,
				.gateway       = gateway_bin.addr4,
				.table_coerced = nm_platform_route_table_coerce (route_table),
				.metric        = route_metric,
			};
		} else {
			r.r6 = (NMPlatformIP6Route) {
				.rt_source     = NM_IP_CONFIG_SOURCE_USER,
				.gateway       = gateway_bin.addr6,
				.table_coerced = nm_platform_route_table_coerce (route_table),
				.metric        = route_metric,
			};
		}

		_nm_l3_config_data_add_route (self, addr_family, ifindex, NULL, &r.rx, NULL, NULL);
	}

	naddresses = nm_setting_ip_config_get_num_addresses (s_ip);
	for (i = 0; i < naddresses; i++) {
		NMIPAddress *s_addr = nm_setting_ip_config_get_address (s_ip, i);
		NMPlatformIPXAddress a;
		NMIPAddr addr_bin;
		GVariant *label;

		nm_assert (nm_ip_address_get_family (s_addr) == addr_family);

		nm_ip_address_get_address_binary (s_addr, &addr_bin);

		if (IS_IPv4) {
			a.a4 = (NMPlatformIP4Address) {
				.address      = addr_bin.addr4,
				.peer_address = addr_bin.addr4,
				.plen         = nm_ip_address_get_prefix (s_addr),
				.lifetime     = NM_PLATFORM_LIFETIME_PERMANENT,
				.preferred    = NM_PLATFORM_LIFETIME_PERMANENT,
				.addr_source  = NM_IP_CONFIG_SOURCE_USER,
			};
			label = nm_ip_address_get_attribute (s_addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
			if (label)
				g_strlcpy (a.a4.label, g_variant_get_string (label, NULL), sizeof (a.a4.label));

			nm_assert (a.a4.plen <= 32);
		} else {
			a.a6 = (NMPlatformIP6Address) {
				.address     = addr_bin.addr6,
				.plen        = nm_ip_address_get_prefix (s_addr),
				.lifetime    = NM_PLATFORM_LIFETIME_PERMANENT,
				.preferred   = NM_PLATFORM_LIFETIME_PERMANENT,
				.addr_source = NM_IP_CONFIG_SOURCE_USER,
			};

			nm_assert (a.a6.plen <= 128);
		}

		_nm_l3_config_data_add_address (self, addr_family, ifindex, NULL, &a.ax);
	}

	nroutes = nm_setting_ip_config_get_num_routes (s_ip);
	for (i = 0; i < nroutes; i++) {
		NMIPRoute *s_route = nm_setting_ip_config_get_route (s_ip, i);
		NMPlatformIPXRoute r;
		NMIPAddr network_bin;
		NMIPAddr next_hop_bin;
		gint64 metric64;
		guint32 metric;
		guint plen;

		nm_assert (nm_ip_route_get_family (s_route) == addr_family);

		nm_ip_route_get_dest_binary (s_route, &network_bin);
		nm_ip_route_get_next_hop_binary (s_route, &next_hop_bin);

		metric64 = nm_ip_route_get_metric (s_route);
		if (metric64 < 0)
			metric = route_metric;
		else
			metric = metric64;
		metric = nm_utils_ip_route_metric_normalize (addr_family, metric);

		plen = nm_ip_route_get_prefix (s_route);

		nm_utils_ipx_address_clear_host_address (addr_family, &network_bin, &network_bin, plen);

		if (IS_IPv4) {
			r.r4 = (NMPlatformIP4Route) {
				.network   = network_bin.addr4,
				.plen      = nm_ip_route_get_prefix (s_route),
				.gateway   = next_hop_bin.addr4,
				.metric    = metric,
				.rt_source = NM_IP_CONFIG_SOURCE_USER,
			};
			nm_assert (r.r4.plen <= 32);
		} else {
			r.r6 = (NMPlatformIP6Route) {
				.network   = network_bin.addr6,
				.plen      = nm_ip_route_get_prefix (s_route),
				.gateway   = next_hop_bin.addr6,
				.metric    = metric,
				.rt_source = NM_IP_CONFIG_SOURCE_USER,
			};
			nm_assert (r.r6.plen <= 128);
		}

		nm_utils_ip_route_attribute_to_platform (addr_family,
		                                         s_route,
		                                         &r.rx,
		                                         route_table);

		_nm_l3_config_data_add_route (self, addr_family, ifindex, NULL, &r.rx, NULL, NULL);
	}

	nnameservers = nm_setting_ip_config_get_num_dns (s_ip);
	for (i = 0; i < nnameservers; i++) {
		const char *s;
		NMIPAddr ip;

		s = nm_setting_ip_config_get_dns (s_ip, i);
		if (!nm_utils_parse_inaddr_bin (addr_family, s, NULL, &ip))
			continue;
		g_array_append_vals (_garray_ensure_for_addrbin (&self->nameservers_x[IS_IPv4], addr_family),
		                     &ip,
		                     1);
	}

	nsearches = nm_setting_ip_config_get_num_dns_searches (s_ip);
	for (i = 0; i < nsearches; i++) {
		_nm_l3_config_data_add_search (self,
		                               addr_family,
		                               nm_setting_ip_config_get_dns_search (s_ip, i));
	}

	idx = 0;
	while ((idx = nm_setting_ip_config_next_valid_dns_option (s_ip, i)) >= 0) {
		_nm_l3_config_data_add_dns_option (self,
		                                   addr_family,
		                                   nm_setting_ip_config_get_dns_option (s_ip, i));
		idx++;
	}

	_nm_l3_config_data_set_dns_priority (self,
	                                     addr_family,
	                                     nm_setting_ip_config_get_dns_priority (s_ip));
}

NML3ConfigData *
nm_l3_config_data_new_from_connection (NMDedupMultiIndex *multi_index,
                                       int ifindex,
                                       NMConnection *connection,
                                       NMSettingConnectionMdns mdns,
                                       NMSettingConnectionLlmnr llmnr,
                                       guint32 route_table,
                                       guint32 route_metric)
{
	NML3ConfigData *self;

	self = nm_l3_config_data_new (multi_index);

	_init_from_connection_ip (self, AF_INET,  ifindex, connection, route_table, route_metric);
	_init_from_connection_ip (self, AF_INET6, ifindex, connection, route_table, route_metric);

	self->mdns = mdns;
	self->llmnr = llmnr;

	return self;
}
