/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2008–2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_IP4_CONFIG_H__
#define __NETWORKMANAGER_IP4_CONFIG_H__

#include "nm-setting-connection.h"

#include "nm-setting-ip4-config.h"

#include "nm-glib-aux/nm-dedup-multi.h"
#include "platform/nmp-object.h"

/*****************************************************************************/

typedef struct {
	NMDedupMultiIdxType parent;
	NMPObjectType obj_type;
} NMIPConfigDedupMultiIdxType;

void nm_ip_config_dedup_multi_idx_type_init (NMIPConfigDedupMultiIdxType *idx_type, NMPObjectType obj_type);

/*****************************************************************************/

void nm_ip_config_iter_ip4_address_init (NMDedupMultiIter *iter, const NMIP4Config *self);
void nm_ip_config_iter_ip4_route_init (NMDedupMultiIter *iter, const NMIP4Config *self);

static inline gboolean
nm_ip_config_iter_ip4_address_next (NMDedupMultiIter *ipconf_iter, const NMPlatformIP4Address **out_address)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (ipconf_iter);
	if (out_address)
		*out_address = has_next ? NMP_OBJECT_CAST_IP4_ADDRESS (ipconf_iter->current->obj) : NULL;
	return has_next;
}

static inline gboolean
nm_ip_config_iter_ip4_route_next (NMDedupMultiIter *ipconf_iter, const NMPlatformIP4Route **out_route)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (ipconf_iter);
	if (out_route)
		*out_route = has_next ? NMP_OBJECT_CAST_IP4_ROUTE (ipconf_iter->current->obj) : NULL;
	return has_next;
}

#define nm_ip_config_iter_ip4_address_for_each(iter, self, address) \
    for (nm_ip_config_iter_ip4_address_init ((iter), (self)); \
         nm_ip_config_iter_ip4_address_next ((iter), (address)); \
         )

#define nm_ip_config_iter_ip4_route_for_each(iter, self, route) \
    for (nm_ip_config_iter_ip4_route_init ((iter), (self)); \
         nm_ip_config_iter_ip4_route_next ((iter), (route)); \
         )

/*****************************************************************************/

static inline gboolean
nm_ip_config_best_default_route_is (const NMPObject *obj)
{
	const NMPlatformIPRoute *r = NMP_OBJECT_CAST_IP_ROUTE (obj);

	/* return whether @obj is considered a default-route.
	 *
	 * NMIP4Config/NMIP6Config tracks the (best) default-route explicitly, because
	 * at various places we act differently depending on whether there is a default-route
	 * configured.
	 *
	 * Note that this only considers the main routing table. */
	return    r
	       && NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r)
	       && nm_platform_route_table_is_main (r->table_coerced);
}

const NMPObject *_nm_ip_config_best_default_route_find_better (const NMPObject *obj_cur, const NMPObject *obj_cmp);
gboolean _nm_ip_config_best_default_route_set (const NMPObject **best_default_route, const NMPObject *new_candidate);
gboolean _nm_ip_config_best_default_route_merge (const NMPObject **best_default_route, const NMPObject *new_candidate);

/*****************************************************************************/

gboolean _nm_ip_config_add_obj (NMDedupMultiIndex *multi_idx,
                                NMIPConfigDedupMultiIdxType *idx_type,
                                int ifindex,
                                const NMPObject *obj_new,
                                const NMPlatformObject *pl_new,
                                gboolean merge,
                                gboolean append_force,
                                const NMPObject **out_obj_old,
                                const NMPObject **out_obj_new);

const NMDedupMultiEntry *_nm_ip_config_lookup_ip_route (const NMDedupMultiIndex *multi_idx,
                                                        const NMIPConfigDedupMultiIdxType *idx_type,
                                                        const NMPObject *needle,
                                                        NMPlatformIPRouteCmpType cmp_type);

void _nm_ip_config_merge_route_attributes (int addr_family,
                                           NMIPRoute *s_route,
                                           NMPlatformIPRoute *r,
                                           guint32 route_table);

/*****************************************************************************/

#define NM_TYPE_IP4_CONFIG (nm_ip4_config_get_type ())
#define NM_IP4_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP4_CONFIG, NMIP4Config))
#define NM_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))
#define NM_IS_IP4_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP4_CONFIG))
#define NM_IS_IP4_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_IP4_CONFIG))
#define NM_IP4_CONFIG_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP4_CONFIG, NMIP4ConfigClass))

typedef struct _NMIP4ConfigClass NMIP4ConfigClass;

/* internal */
#define NM_IP4_CONFIG_MULTI_IDX "multi-idx"
#define NM_IP4_CONFIG_IFINDEX "ifindex"

/* public*/
#define NM_IP4_CONFIG_ADDRESS_DATA "address-data"
#define NM_IP4_CONFIG_ROUTE_DATA "route-data"
#define NM_IP4_CONFIG_GATEWAY "gateway"
#define NM_IP4_CONFIG_NAMESERVER_DATA "nameserver-data"
#define NM_IP4_CONFIG_DOMAINS "domains"
#define NM_IP4_CONFIG_SEARCHES "searches"
#define NM_IP4_CONFIG_DNS_OPTIONS "dns-options"
#define NM_IP4_CONFIG_DNS_PRIORITY "dns-priority"
#define NM_IP4_CONFIG_WINS_SERVER_DATA "wins-server-data"

/* deprecated */
#define NM_IP4_CONFIG_ADDRESSES "addresses"
#define NM_IP4_CONFIG_ROUTES "routes"
#define NM_IP4_CONFIG_NAMESERVERS "nameservers"
#define NM_IP4_CONFIG_WINS_SERVERS "wins-servers"

GType nm_ip4_config_get_type (void);

NMIP4Config * nm_ip4_config_new (NMDedupMultiIndex *multi_idx,
                                 int ifindex);

NMIP4Config *nm_ip4_config_clone (const NMIP4Config *self);
int nm_ip4_config_get_ifindex (const NMIP4Config *self);

NMDedupMultiIndex *nm_ip4_config_get_multi_idx (const NMIP4Config *self);

NMIP4Config *nm_ip4_config_capture (NMDedupMultiIndex *multi_idx, NMPlatform *platform, int ifindex);

void nm_ip4_config_add_dependent_routes (NMIP4Config *self,
                                         guint32 route_table,
                                         guint32 route_metric,
                                         GPtrArray **out_ip4_dev_route_blacklist);

gboolean nm_ip4_config_commit (const NMIP4Config *self,
                               NMPlatform *platform,
                               NMIPRouteTableSyncMode route_table_sync);

void nm_ip4_config_merge_setting (NMIP4Config *self,
                                  NMSettingIPConfig *setting,
                                  NMSettingConnectionMdns mdns,
                                  NMSettingConnectionLlmnr llmnr,
                                  guint32 route_table,
                                  guint32 route_metric);
NMSetting *nm_ip4_config_create_setting (const NMIP4Config *self);

void nm_ip4_config_merge (NMIP4Config *dst,
                          const NMIP4Config *src,
                          NMIPConfigMergeFlags merge_flags,
                          guint32 default_route_metric_penalty);
void nm_ip4_config_subtract (NMIP4Config *dst,
                             const NMIP4Config *src,
                             guint32 default_route_metric_penalty);
void nm_ip4_config_intersect (NMIP4Config *dst,
                              const NMIP4Config *src,
                              gboolean intersect_addresses,
                              gboolean intersect_routes,
                              guint32 default_route_metric_penalty);
NMIP4Config *nm_ip4_config_intersect_alloc (const NMIP4Config *a,
                                            const NMIP4Config *b,
                                            gboolean intersect_addresses,
                                            gboolean intersect_routes,
                                            guint32 default_route_metric_penalty);
gboolean nm_ip4_config_replace (NMIP4Config *dst, const NMIP4Config *src, gboolean *relevant_changes);

const NMPObject *nm_ip4_config_best_default_route_get (const NMIP4Config *self);
const NMPObject *_nm_ip4_config_best_default_route_find (const NMIP4Config *self);

in_addr_t nmtst_ip4_config_get_gateway (NMIP4Config *config);

NMSettingConnectionMdns nm_ip4_config_mdns_get (const NMIP4Config *self);
void                    nm_ip4_config_mdns_set (NMIP4Config *self,
                                                NMSettingConnectionMdns mdns);
NMSettingConnectionLlmnr nm_ip4_config_llmnr_get (const NMIP4Config *self);
void                     nm_ip4_config_llmnr_set (NMIP4Config *self,
                                                  NMSettingConnectionLlmnr llmnr);

const NMDedupMultiHeadEntry *nm_ip4_config_lookup_addresses (const NMIP4Config *self);
void nm_ip4_config_reset_addresses (NMIP4Config *self);
void nm_ip4_config_add_address (NMIP4Config *self, const NMPlatformIP4Address *address);
void _nmtst_ip4_config_del_address (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_addresses (const NMIP4Config *self);
const NMPlatformIP4Address *nm_ip4_config_get_first_address (const NMIP4Config *self);
const NMPlatformIP4Address *_nmtst_ip4_config_get_address (const NMIP4Config *self, guint i);
gboolean nm_ip4_config_address_exists (const NMIP4Config *self, const NMPlatformIP4Address *address);

const NMDedupMultiHeadEntry *nm_ip4_config_lookup_routes (const NMIP4Config *self);
void nm_ip4_config_reset_routes (NMIP4Config *self);
void nm_ip4_config_add_route (NMIP4Config *self,
                              const NMPlatformIP4Route *route,
                              const NMPObject **out_obj_new);
void _nmtst_ip4_config_del_route (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_routes (const NMIP4Config *self);
const NMPlatformIP4Route *_nmtst_ip4_config_get_route (const NMIP4Config *self, guint i);

const NMPlatformIP4Route *nm_ip4_config_get_direct_route_for_host (const NMIP4Config *self,
                                                                   in_addr_t host,
                                                                   guint32 route_table);
void nm_ip4_config_update_routes_metric (NMIP4Config *self, gint64 metric);

void nm_ip4_config_reset_nameservers (NMIP4Config *self);
void nm_ip4_config_add_nameserver (NMIP4Config *self, guint32 nameserver);

static inline void
_nm_ip4_config_add_nameserver (NMIP4Config *self, const guint32 *nameserver)
{
	nm_ip4_config_add_nameserver (self, *nameserver);
}

void nm_ip4_config_del_nameserver (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_nameservers (const NMIP4Config *self);
guint32 nm_ip4_config_get_nameserver (const NMIP4Config *self, guint i);
const in_addr_t *_nm_ip4_config_get_nameserver (const NMIP4Config *self, guint i);

void nm_ip4_config_reset_domains (NMIP4Config *self);
void nm_ip4_config_add_domain (NMIP4Config *self, const char *domain);
void nm_ip4_config_del_domain (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_domains (const NMIP4Config *self);
const char * nm_ip4_config_get_domain (const NMIP4Config *self, guint i);

void nm_ip4_config_reset_searches (NMIP4Config *self);
void nm_ip4_config_add_search (NMIP4Config *self, const char *search);
void nm_ip4_config_del_search (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_searches (const NMIP4Config *self);
const char * nm_ip4_config_get_search (const NMIP4Config *self, guint i);

void nm_ip4_config_reset_dns_options (NMIP4Config *self);
void nm_ip4_config_add_dns_option (NMIP4Config *self, const char *option);
void nm_ip4_config_del_dns_option (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_dns_options (const NMIP4Config *self);
const char * nm_ip4_config_get_dns_option (const NMIP4Config *self, guint i);

void nm_ip4_config_set_dns_priority (NMIP4Config *self, int priority);
int nm_ip4_config_get_dns_priority (const NMIP4Config *self);

void nm_ip4_config_reset_nis_servers (NMIP4Config *self);
void nm_ip4_config_add_nis_server (NMIP4Config *self, guint32 nis);
void nm_ip4_config_del_nis_server (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_nis_servers (const NMIP4Config *self);
guint32 nm_ip4_config_get_nis_server (const NMIP4Config *self, guint i);
void nm_ip4_config_set_nis_domain (NMIP4Config *self, const char *domain);
const char * nm_ip4_config_get_nis_domain (const NMIP4Config *self);

void nm_ip4_config_reset_wins (NMIP4Config *self);
void nm_ip4_config_add_wins (NMIP4Config *self, guint32 wins);
void nm_ip4_config_del_wins (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_wins (const NMIP4Config *self);
guint32 nm_ip4_config_get_wins (const NMIP4Config *self, guint i);

void nm_ip4_config_set_mtu (NMIP4Config *self, guint32 mtu, NMIPConfigSource source);
guint32 nm_ip4_config_get_mtu (const NMIP4Config *self);
NMIPConfigSource nm_ip4_config_get_mtu_source (const NMIP4Config *self);

void nm_ip4_config_set_metered (NMIP4Config *self, gboolean metered);
gboolean nm_ip4_config_get_metered (const NMIP4Config *self);

const NMPObject *nm_ip4_config_nmpobj_lookup (const NMIP4Config *self,
                                              const NMPObject *needle);
gboolean nm_ip4_config_nmpobj_remove (NMIP4Config *self,
                                      const NMPObject *needle);

void nm_ip4_config_hash (const NMIP4Config *self, GChecksum *sum, gboolean dns_only);
gboolean nm_ip4_config_equal (const NMIP4Config *a, const NMIP4Config *b);

gboolean _nm_ip_config_check_and_add_domain (GPtrArray *array, const char *domain);

void nm_ip_config_dump (const NMIPConfig *self,
                        const char *detail,
                        NMLogLevel level,
                        NMLogDomain domain);

/*****************************************************************************/

#include "nm-ip6-config.h"

static inline gboolean
NM_IS_IP_CONFIG (gconstpointer config, int addr_family)
{
	if (addr_family == AF_UNSPEC)
		return NM_IS_IP4_CONFIG (config) || NM_IS_IP6_CONFIG (config);
	if (addr_family == AF_INET)
		return NM_IS_IP4_CONFIG (config);
	if (addr_family == AF_INET6)
		return NM_IS_IP6_CONFIG (config);
	g_return_val_if_reached (FALSE);
}

#if _NM_CC_SUPPORT_GENERIC
/* _NM_IS_IP_CONFIG() is a bit unusual. If _Generic() is supported,
 * it checks whether @config is either NM_IS_IP4_CONFIG() or NM_IS_IP6_CONFIG(),
 * depending on the pointer type of @config.
 *
 * For example, with _Generic() support, the following assertions would fail:
 *    NMIP6Config *ptr = (NMIP6Config *) nm_ip4_config_new(...);
 *    g_assert (_NM_IS_IP_CONFIG (ptr, ptr));
 * but the following would pass:
 *    NMIP4Config *ptr = nm_ip4_config_new(...);
 *    g_assert (_NM_IS_IP_CONFIG (ptr, ptr));
 */
#define _NM_IS_IP_CONFIG(typeexpr, config) \
	({ \
		const void *const _config = (config); \
		_Generic ((typeexpr), \
		          const void        *const: (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		          const void        *     : (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		                void        *const: (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		                void        *     : (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		          const NMIPConfig  *const: (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		          const NMIPConfig  *     : (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		                NMIPConfig  *const: (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		                NMIPConfig  *     : (NM_IS_IP4_CONFIG (_config) || NM_IS_IP6_CONFIG (_config)), \
		          const NMIP4Config *const: (NM_IS_IP4_CONFIG (_config)), \
		          const NMIP4Config *     : (NM_IS_IP4_CONFIG (_config)), \
		                NMIP4Config *const: (NM_IS_IP4_CONFIG (_config)), \
		                NMIP4Config *     : (NM_IS_IP4_CONFIG (_config)), \
		          const NMIP6Config *const: (NM_IS_IP6_CONFIG (_config)), \
		          const NMIP6Config *     : (NM_IS_IP6_CONFIG (_config)), \
		                NMIP6Config *const: (NM_IS_IP6_CONFIG (_config)), \
		                NMIP6Config *     : (NM_IS_IP6_CONFIG (_config))); \
	})
#else
#define _NM_IS_IP_CONFIG(typeexpr, config) NM_IS_IP_CONFIG(config, AF_UNSPEC)
#endif

#define NM_IP_CONFIG_CAST(config) \
	({ \
		const void *const _configx = (config); \
		\
		nm_assert (!_configx || _NM_IS_IP_CONFIG ((config), _configx)); \
		NM_CONSTCAST_FULL (NMIPConfig, (config), _configx, NMIP4Config, NMIP6Config); \
	})

static inline int
nm_ip_config_get_addr_family (const NMIPConfig *config)
{
	if (NM_IS_IP4_CONFIG (config))
		return AF_INET;
	if (NM_IS_IP6_CONFIG (config))
		return AF_INET6;
	g_return_val_if_reached (AF_UNSPEC);
}

#define _NM_IP_CONFIG_DISPATCH(config, v4_func, v6_func, ...) \
	G_STMT_START { \
		gconstpointer _config = (config); \
		\
		if (NM_IS_IP4_CONFIG (_config)) { \
			return v4_func ((NMIP4Config *) _config, ##__VA_ARGS__); \
		} else { \
			nm_assert (NM_IS_IP6_CONFIG (_config)); \
			return v6_func ((NMIP6Config *) _config, ##__VA_ARGS__); \
		} \
	} G_STMT_END

#define _NM_IP_CONFIG_DISPATCH_VOID(config, v4_func, v6_func, ...) \
	G_STMT_START { \
		gconstpointer _config = (config); \
		\
		if (NM_IS_IP4_CONFIG (_config)) { \
			v4_func ((NMIP4Config *) _config, ##__VA_ARGS__); \
		} else { \
			nm_assert (NM_IS_IP6_CONFIG (_config)); \
			v6_func ((NMIP6Config *) _config, ##__VA_ARGS__); \
		} \
	} G_STMT_END

static inline int
nm_ip_config_get_ifindex (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_ifindex, nm_ip6_config_get_ifindex);
}

static inline void
nm_ip_config_hash (const NMIPConfig *self, GChecksum *sum, gboolean dns_only)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_hash, nm_ip6_config_hash, sum, dns_only);
}

static inline void
nm_ip_config_add_address (NMIPConfig *self, const NMPlatformIPAddress *address)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_add_address, nm_ip6_config_add_address, (gconstpointer) address);
}

static inline void
nm_ip_config_reset_addresses (NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_reset_addresses, nm_ip6_config_reset_addresses);
}

static inline void
nm_ip_config_add_route (NMIPConfig *self,
                        const NMPlatformIPRoute *new,
                        const NMPObject **out_obj_new)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_add_route, nm_ip6_config_add_route, (gpointer) new, out_obj_new);
}

static inline void
nm_ip_config_reset_routes (NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_reset_routes, nm_ip6_config_reset_routes);
}

static inline int
nm_ip_config_get_dns_priority (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_dns_priority, nm_ip6_config_get_dns_priority);
}

static inline void
nm_ip_config_set_dns_priority (NMIPConfig *self, int priority)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_set_dns_priority, nm_ip6_config_set_dns_priority, priority);
}

static inline void
nm_ip_config_add_nameserver (NMIPConfig *self, const NMIPAddr *ns)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, _nm_ip4_config_add_nameserver, nm_ip6_config_add_nameserver, (gconstpointer) ns);
}

static inline void
nm_ip_config_reset_nameservers (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_reset_nameservers, nm_ip6_config_reset_nameservers);
}

static inline guint
nm_ip_config_get_num_nameservers (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_num_nameservers, nm_ip6_config_get_num_nameservers);
}

static inline gconstpointer
nm_ip_config_get_nameserver (const NMIPConfig *self, guint i)
{
	_NM_IP_CONFIG_DISPATCH (self, _nm_ip4_config_get_nameserver, nm_ip6_config_get_nameserver, i);
}

static inline guint
nm_ip_config_get_num_domains (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_num_domains, nm_ip6_config_get_num_domains);
}

static inline const char *
nm_ip_config_get_domain (const NMIPConfig *self, guint i)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_domain, nm_ip6_config_get_domain, i);
}

static inline void
nm_ip_config_reset_searches (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_reset_searches, nm_ip6_config_reset_searches);
}

static inline void
nm_ip_config_add_search (const NMIPConfig *self, const char *new)
{
	_NM_IP_CONFIG_DISPATCH_VOID (self, nm_ip4_config_add_search, nm_ip6_config_add_search, new);
}

static inline guint
nm_ip_config_get_num_searches (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_num_searches, nm_ip6_config_get_num_searches);
}

static inline const char *
nm_ip_config_get_search (const NMIPConfig *self, guint i)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_search, nm_ip6_config_get_search, i);
}

static inline guint
nm_ip_config_get_num_dns_options (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_num_dns_options, nm_ip6_config_get_num_dns_options);
}

static inline const char *
nm_ip_config_get_dns_option (const NMIPConfig *self, guint i)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_get_dns_option, nm_ip6_config_get_dns_option, i);
}

static inline const NMPObject *
nm_ip_config_best_default_route_get (const NMIPConfig *self)
{
	_NM_IP_CONFIG_DISPATCH (self, nm_ip4_config_best_default_route_get, nm_ip6_config_best_default_route_get);
}

#define _NM_IP_CONFIG_DISPATCH_SET_OP(_return, dst, src, v4_func, v6_func, ...) \
	G_STMT_START { \
		gpointer _dst = (dst); \
		gconstpointer _src = (src); \
		\
		if (NM_IS_IP4_CONFIG (_dst)) { \
			nm_assert (NM_IS_IP4_CONFIG (_src)); \
			_return v4_func ((NMIP4Config *) _dst, (const NMIP4Config *) _src, ##__VA_ARGS__); \
		} else { \
			nm_assert (NM_IS_IP6_CONFIG (_src)); \
			_return v6_func ((NMIP6Config *) _dst, (const NMIP6Config *) _src, ##__VA_ARGS__); \
		} \
	} G_STMT_END

static inline void
nm_ip_config_intersect (NMIPConfig *dst,
                        const NMIPConfig *src,
                        gboolean intersect_addresses,
                        gboolean intersect_routes,
                        guint32 default_route_metric_penalty)
{
	_NM_IP_CONFIG_DISPATCH_SET_OP (, dst, src,
	                               nm_ip4_config_intersect,
	                               nm_ip6_config_intersect,
	                               intersect_addresses,
	                               intersect_routes,
	                               default_route_metric_penalty);
}

static inline void
nm_ip_config_subtract (NMIPConfig *dst,
                       const NMIPConfig *src,
                       guint32 default_route_metric_penalty)
{
	_NM_IP_CONFIG_DISPATCH_SET_OP (, dst, src,
	                               nm_ip4_config_subtract,
	                               nm_ip6_config_subtract,
	                               default_route_metric_penalty);
}

static inline void
nm_ip_config_merge (NMIPConfig *dst,
                    const NMIPConfig *src,
                    NMIPConfigMergeFlags merge_flags,
                    guint32 default_route_metric_penalty)
{
	_NM_IP_CONFIG_DISPATCH_SET_OP (, dst, src,
	                               nm_ip4_config_merge,
	                               nm_ip6_config_merge,
	                               merge_flags,
	                               default_route_metric_penalty);
}

static inline gboolean
nm_ip_config_replace (NMIPConfig *dst,
                      const NMIPConfig *src,
                      gboolean *relevant_changes)
{
	_NM_IP_CONFIG_DISPATCH_SET_OP (return, dst, src,
	                               nm_ip4_config_replace,
	                               nm_ip6_config_replace,
	                               relevant_changes);
}

static inline NMIPConfig *
nm_ip_config_intersect_alloc (const NMIPConfig *a,
                              const NMIPConfig *b,
                              gboolean intersect_addresses,
                              gboolean intersect_routes,
                              guint32 default_route_metric_penalty)
{
	if (NM_IS_IP4_CONFIG (a)) {
		nm_assert (NM_IS_IP4_CONFIG (b));
		return (NMIPConfig *) nm_ip4_config_intersect_alloc ((const NMIP4Config *) a,
		                                                     (const NMIP4Config *) b,
		                                                     intersect_addresses,
		                                                     intersect_routes,
		                                                     default_route_metric_penalty);
	} else {
		nm_assert (NM_IS_IP6_CONFIG (a));
		nm_assert (NM_IS_IP6_CONFIG (b));
		return (NMIPConfig *) nm_ip6_config_intersect_alloc ((const NMIP6Config *) a,
		                                                     (const NMIP6Config *) b,
		                                                     intersect_addresses,
		                                                     intersect_routes,
		                                                     default_route_metric_penalty);
	}
}

#endif /* __NETWORKMANAGER_IP4_CONFIG_H__ */
