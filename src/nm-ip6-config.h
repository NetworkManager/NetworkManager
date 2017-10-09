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

#ifndef __NETWORKMANAGER_IP6_CONFIG_H__
#define __NETWORKMANAGER_IP6_CONFIG_H__

#include <netinet/in.h>

#include "nm-exported-object.h"
#include "nm-setting-ip6-config.h"

#include "nm-utils/nm-dedup-multi.h"
#include "platform/nmp-object.h"

/*****************************************************************************/

void nm_ip_config_iter_ip6_address_init (NMDedupMultiIter *iter, const NMIP6Config *self);
void nm_ip_config_iter_ip6_route_init (NMDedupMultiIter *iter, const NMIP6Config *self);

static inline gboolean
nm_ip_config_iter_ip6_address_next (NMDedupMultiIter *ipconf_iter, const NMPlatformIP6Address **out_address)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (ipconf_iter);
	if (out_address)
		*out_address = has_next ? NMP_OBJECT_CAST_IP6_ADDRESS (ipconf_iter->current->obj) : NULL;
	return has_next;
}

static inline gboolean
nm_ip_config_iter_ip6_route_next (NMDedupMultiIter *ipconf_iter, const NMPlatformIP6Route **out_route)
{
	gboolean has_next;

	has_next = nm_dedup_multi_iter_next (ipconf_iter);
	if (out_route)
		*out_route = has_next ? NMP_OBJECT_CAST_IP6_ROUTE (ipconf_iter->current->obj) : NULL;
	return has_next;
}

#define nm_ip_config_iter_ip6_address_for_each(iter, self, address) \
    for (nm_ip_config_iter_ip6_address_init ((iter), (self)); \
         nm_ip_config_iter_ip6_address_next ((iter), (address)); \
         )

#define nm_ip_config_iter_ip6_route_for_each(iter, self, route) \
    for (nm_ip_config_iter_ip6_route_init ((iter), (self)); \
         nm_ip_config_iter_ip6_route_next ((iter), (route)); \
         )

/*****************************************************************************/

#define NM_TYPE_IP6_CONFIG (nm_ip6_config_get_type ())
#define NM_IP6_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_IP6_CONFIG, NMIP6Config))
#define NM_IP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_IP6_CONFIG, NMIP6ConfigClass))
#define NM_IS_IP6_CONFIG(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_IP6_CONFIG))
#define NM_IS_IP6_CONFIG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_IP6_CONFIG))
#define NM_IP6_CONFIG_GET_CLASS(obj) (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_IP6_CONFIG, NMIP6ConfigClass))

typedef struct _NMIP6ConfigClass NMIP6ConfigClass;

/* internal */
#define NM_IP6_CONFIG_MULTI_IDX "multi-idx"
#define NM_IP6_CONFIG_IFINDEX "ifindex"

/* public */
#define NM_IP6_CONFIG_ADDRESS_DATA "address-data"
#define NM_IP6_CONFIG_ROUTE_DATA "route-data"
#define NM_IP6_CONFIG_GATEWAY "gateway"
#define NM_IP6_CONFIG_NAMESERVERS "nameservers"
#define NM_IP6_CONFIG_DOMAINS "domains"
#define NM_IP6_CONFIG_SEARCHES "searches"
#define NM_IP6_CONFIG_DNS_OPTIONS "dns-options"
#define NM_IP6_CONFIG_DNS_PRIORITY "dns-priority"

/* deprecated */
#define NM_IP6_CONFIG_ADDRESSES "addresses"
#define NM_IP6_CONFIG_ROUTES "routes"

GType nm_ip6_config_get_type (void);


NMIP6Config * nm_ip6_config_new (struct _NMDedupMultiIndex *multi_idx, int ifindex);
NMIP6Config * nm_ip6_config_new_cloned (const NMIP6Config *src);

int nm_ip6_config_get_ifindex (const NMIP6Config *self);

struct _NMDedupMultiIndex *nm_ip6_config_get_multi_idx (const NMIP6Config *self);

NMIP6Config *nm_ip6_config_capture (struct _NMDedupMultiIndex *multi_idx, NMPlatform *platform, int ifindex,
                                    gboolean capture_resolv_conf, NMSettingIP6ConfigPrivacy use_temporary);

void nm_ip6_config_add_dependent_routes (NMIP6Config *self,
                                         guint32 route_table,
                                         guint32 route_metric);

gboolean nm_ip6_config_commit (const NMIP6Config *self,
                               NMPlatform *platform,
                               NMIPRouteTableSyncMode route_table_sync,
                               GPtrArray **out_temporary_not_available);
void nm_ip6_config_merge_setting (NMIP6Config *self,
                                  NMSettingIPConfig *setting,
                                  guint32 route_table,
                                  guint32 route_metric);
NMSetting *nm_ip6_config_create_setting (const NMIP6Config *self);


void nm_ip6_config_merge (NMIP6Config *dst,
                          const NMIP6Config *src,
                          NMIPConfigMergeFlags merge_flags,
                          guint32 default_route_metric_penalty);
void nm_ip6_config_subtract (NMIP6Config *dst,
                             const NMIP6Config *src,
                             guint32 default_route_metric_penalty);
void nm_ip6_config_intersect (NMIP6Config *dst,
                              const NMIP6Config *src,
                              guint32 default_route_metric_penalty);
gboolean nm_ip6_config_replace (NMIP6Config *dst, const NMIP6Config *src, gboolean *relevant_changes);
void nm_ip6_config_dump (const NMIP6Config *self, const char *detail);

const NMPObject *nm_ip6_config_best_default_route_get (const NMIP6Config *self);
const NMPObject *_nm_ip6_config_best_default_route_find (const NMIP6Config *self);

const NMDedupMultiHeadEntry *nm_ip6_config_lookup_addresses (const NMIP6Config *self);
void nm_ip6_config_reset_addresses (NMIP6Config *self);
void nm_ip6_config_add_address (NMIP6Config *self, const NMPlatformIP6Address *address);
void _nmtst_ip6_config_del_address (NMIP6Config *self, guint i);
guint nm_ip6_config_get_num_addresses (const NMIP6Config *self);
const NMPlatformIP6Address *nm_ip6_config_get_first_address (const NMIP6Config *self);
const NMPlatformIP6Address *_nmtst_ip6_config_get_address (const NMIP6Config *self, guint i);
const NMPlatformIP6Address *nm_ip6_config_get_address_first_nontentative (const NMIP6Config *self, gboolean linklocal);
gboolean nm_ip6_config_address_exists (const NMIP6Config *self, const NMPlatformIP6Address *address);
const NMPlatformIP6Address *nm_ip6_config_lookup_address (const NMIP6Config *self,
                                                          const struct in6_addr *addr);
gboolean _nmtst_ip6_config_addresses_sort (NMIP6Config *self);
gboolean nm_ip6_config_has_any_dad_pending (const NMIP6Config *self,
                                            const NMIP6Config *candidates);

const NMDedupMultiHeadEntry *nm_ip6_config_lookup_routes (const NMIP6Config *self);
void nm_ip6_config_reset_routes (NMIP6Config *self);
void nm_ip6_config_add_route (NMIP6Config *self,
                              const NMPlatformIP6Route *route,
                              const NMPObject **out_obj_new);
void _nmtst_ip6_config_del_route (NMIP6Config *self, guint i);
guint nm_ip6_config_get_num_routes (const NMIP6Config *self);
const NMPlatformIP6Route *_nmtst_ip6_config_get_route (const NMIP6Config *self, guint i);

const NMPlatformIP6Route *nm_ip6_config_get_direct_route_for_host (const NMIP6Config *self,
                                                                   const struct in6_addr *host,
                                                                   guint32 route_table);
const NMPlatformIP6Address *nm_ip6_config_get_subnet_for_host (const NMIP6Config *self, const struct in6_addr *host);

void nm_ip6_config_reset_nameservers (NMIP6Config *self);
void nm_ip6_config_add_nameserver (NMIP6Config *self, const struct in6_addr *nameserver);
void nm_ip6_config_del_nameserver (NMIP6Config *self, guint i);
guint nm_ip6_config_get_num_nameservers (const NMIP6Config *self);
const struct in6_addr *nm_ip6_config_get_nameserver (const NMIP6Config *self, guint i);

void nm_ip6_config_reset_domains (NMIP6Config *self);
void nm_ip6_config_add_domain (NMIP6Config *self, const char *domain);
void nm_ip6_config_del_domain (NMIP6Config *self, guint i);
guint nm_ip6_config_get_num_domains (const NMIP6Config *self);
const char * nm_ip6_config_get_domain (const NMIP6Config *self, guint i);

void nm_ip6_config_reset_searches (NMIP6Config *self);
void nm_ip6_config_add_search (NMIP6Config *self, const char *search);
void nm_ip6_config_del_search (NMIP6Config *self, guint i);
guint nm_ip6_config_get_num_searches (const NMIP6Config *self);
const char * nm_ip6_config_get_search (const NMIP6Config *self, guint i);

void nm_ip6_config_reset_dns_options (NMIP6Config *self);
void nm_ip6_config_add_dns_option (NMIP6Config *self, const char *option);
void nm_ip6_config_del_dns_option (NMIP6Config *self, guint i);
guint nm_ip6_config_get_num_dns_options (const NMIP6Config *self);
const char * nm_ip6_config_get_dns_option (const NMIP6Config *self, guint i);

void nm_ip6_config_set_dns_priority (NMIP6Config *self, gint priority);
gint nm_ip6_config_get_dns_priority (const NMIP6Config *self);

const NMPObject *nm_ip6_config_nmpobj_lookup (const NMIP6Config *self,
                                              const NMPObject *needle);
gboolean nm_ip6_config_nmpobj_remove (NMIP6Config *self,
                                      const NMPObject *needle);

void nm_ip6_config_hash (const NMIP6Config *self, GChecksum *sum, gboolean dns_only);
gboolean nm_ip6_config_equal (const NMIP6Config *a, const NMIP6Config *b);

void nm_ip6_config_set_privacy (NMIP6Config *self, NMSettingIP6ConfigPrivacy privacy);

struct _NMNDiscAddress;
void nm_ip6_config_reset_addresses_ndisc (NMIP6Config *self,
                                          const struct _NMNDiscAddress *addresses,
                                          guint addresses_n,
                                          guint8 plen,
                                          guint32 ifa_flags);
struct _NMNDiscRoute;
struct _NMNDiscGateway;
void nm_ip6_config_reset_routes_ndisc (NMIP6Config *self,
                                       const struct _NMNDiscGateway *gateways,
                                       guint gateways_n,
                                       const struct _NMNDiscRoute *routes,
                                       guint routes_n,
                                       guint32 route_table,
                                       guint32 route_metric,
                                       gboolean kernel_support_rta_pref);

#endif /* __NETWORKMANAGER_IP6_CONFIG_H__ */
