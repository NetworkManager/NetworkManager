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

#include "nm-exported-object.h"
#include "nm-setting-ip4-config.h"

#include "nm-utils/nm-dedup-multi.h"
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

	/* return whether @obj is considered a default-route, that is, a route
	 * as added by NetworkManager. E.g. if the route is not in the main-table,
	 * it's considered just like a regular route. */
	return    r
	       && !r->table_coerced
	       && NM_PLATFORM_IP_ROUTE_IS_DEFAULT (r);
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
#define NM_IP4_CONFIG_NAMESERVERS "nameservers"
#define NM_IP4_CONFIG_DOMAINS "domains"
#define NM_IP4_CONFIG_SEARCHES "searches"
#define NM_IP4_CONFIG_DNS_OPTIONS "dns-options"
#define NM_IP4_CONFIG_DNS_PRIORITY "dns-priority"
#define NM_IP4_CONFIG_WINS_SERVERS "wins-servers"

/* deprecated */
#define NM_IP4_CONFIG_ADDRESSES "addresses"
#define NM_IP4_CONFIG_ROUTES "routes"

GType nm_ip4_config_get_type (void);


NMIP4Config * nm_ip4_config_new (NMDedupMultiIndex *multi_idx,
                                 int ifindex);

int nm_ip4_config_get_ifindex (const NMIP4Config *self);

NMDedupMultiIndex *nm_ip4_config_get_multi_idx (const NMIP4Config *self);

NMIP4Config *nm_ip4_config_capture (NMDedupMultiIndex *multi_idx, NMPlatform *platform, int ifindex, gboolean capture_resolv_conf);

void nm_ip4_config_add_device_routes (NMIP4Config *self,
                                      guint32 route_table,
                                      guint32 route_metric,
                                      GPtrArray **out_ip4_dev_route_blacklist);

gboolean nm_ip4_config_commit (const NMIP4Config *self,
                               NMPlatform *platform,
                               NMIPRouteTableSyncMode route_table_sync);

void nm_ip4_config_merge_setting (NMIP4Config *self,
                                  NMSettingIPConfig *setting,
                                  guint32 route_table,
                                  guint32 route_metric);
NMSetting *nm_ip4_config_create_setting (const NMIP4Config *self);


void nm_ip4_config_merge (NMIP4Config *dst, const NMIP4Config *src, NMIPConfigMergeFlags merge_flags);
void nm_ip4_config_subtract (NMIP4Config *dst, const NMIP4Config *src);
void nm_ip4_config_intersect (NMIP4Config *dst, const NMIP4Config *src);
gboolean nm_ip4_config_replace (NMIP4Config *dst, const NMIP4Config *src, gboolean *relevant_changes);
gboolean nm_ip4_config_destination_is_direct (const NMIP4Config *self, guint32 dest, guint8 plen);
void nm_ip4_config_dump (const NMIP4Config *self, const char *detail);


void nm_ip4_config_set_never_default (NMIP4Config *self, gboolean never_default);
gboolean nm_ip4_config_get_never_default (const NMIP4Config *self);
void nm_ip4_config_set_gateway (NMIP4Config *self, guint32 gateway);
void nm_ip4_config_unset_gateway (NMIP4Config *self);
gboolean nm_ip4_config_has_gateway (const NMIP4Config *self);
guint32 nm_ip4_config_get_gateway (const NMIP4Config *self);

const NMPObject *nm_ip4_config_best_default_route_get (const NMIP4Config *self);
const NMPObject *_nm_ip4_config_best_default_route_find (const NMIP4Config *self);

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

const NMPlatformIP4Route *nm_ip4_config_get_direct_route_for_host (const NMIP4Config *self, guint32 host);

void nm_ip4_config_reset_nameservers (NMIP4Config *self);
void nm_ip4_config_add_nameserver (NMIP4Config *self, guint32 nameserver);
void nm_ip4_config_del_nameserver (NMIP4Config *self, guint i);
guint nm_ip4_config_get_num_nameservers (const NMIP4Config *self);
guint32 nm_ip4_config_get_nameserver (const NMIP4Config *self, guint i);

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

void nm_ip4_config_set_dns_priority (NMIP4Config *self, gint priority);
gint nm_ip4_config_get_dns_priority (const NMIP4Config *self);

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

#endif /* __NETWORKMANAGER_IP4_CONFIG_H__ */
