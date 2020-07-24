// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_L3_CONFIG_DATA_H__
#define __NM_L3_CONFIG_DATA_H__

#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip6-config.h"
#include "platform/nm-platform.h"

typedef enum {
	NM_L3_CONFIG_DAT_FLAGS_NONE                           = 0,

	/* if set, then the merge flag NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES gets
	 * ignored during merge. */
	NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES = (1ull << 0),
} NML3ConfigDatFlags;

typedef enum {
	NM_L3_CONFIG_ADD_FLAGS_NONE         = 0,

	/* If the object does not yet exist, it will be added. If it already exists,
	 * by default the object will be replaced. With this flag, the new object will
	 * be merged with the existing one. */
	NM_L3_CONFIG_ADD_FLAGS_MERGE        = (1ull << 0),

	/* If the object does not yet exist, it will be added. If it already exists,
	 * by default the object will be replaced. With this flag, the add will have
	 * no effect and the existing object will be kept. */
	NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE    = (1ull << 1),

	/* A new object gets appended by default. If the object already exists,
	 * by default it will not be moved. With APPEND-FORCE, we will always move
	 * an existing object to the end of the list. */
	NM_L3_CONFIG_ADD_FLAGS_APPEND_FORCE = (1ull << 2),
} NML3ConfigAddFlags;

/*****************************************************************************/

typedef struct _NML3ConfigData NML3ConfigData;

NML3ConfigData *nm_l3_config_data_new (NMDedupMultiIndex *multi_idx,
                                       int ifindex);
const NML3ConfigData *nm_l3_config_data_ref (const NML3ConfigData *self);
const NML3ConfigData *nm_l3_config_data_ref_and_seal (const NML3ConfigData *self);
const NML3ConfigData *nm_l3_config_data_seal (const NML3ConfigData *self);
void nm_l3_config_data_unref (const NML3ConfigData *self);

NM_AUTO_DEFINE_FCN0 (const NML3ConfigData *, _nm_auto_unref_l3cfg, nm_l3_config_data_unref);
#define nm_auto_unref_l3cfg nm_auto (_nm_auto_unref_l3cfg)

NM_AUTO_DEFINE_FCN0 (NML3ConfigData *, _nm_auto_unref_l3cfg_init, nm_l3_config_data_unref);
#define nm_auto_unref_l3cfg_init nm_auto (_nm_auto_unref_l3cfg_init)

gboolean nm_l3_config_data_is_sealed (const NML3ConfigData *self);

NML3ConfigData *nm_l3_config_data_new_clone (const NML3ConfigData *src,
                                             int ifindex);

NML3ConfigData *nm_l3_config_data_new_from_connection (NMDedupMultiIndex *multi_idx,
                                                       int ifindex,
                                                       NMConnection *connection,
                                                       NMSettingConnectionMdns mdns,
                                                       NMSettingConnectionLlmnr llmnr,
                                                       guint32 route_table,
                                                       guint32 route_metric);

NML3ConfigData *nm_l3_config_data_new_from_platform (NMDedupMultiIndex *multi_idx,
                                                     int ifindex,
                                                     NMPlatform *platform,
                                                     NMSettingIP6ConfigPrivacy ipv6_privacy_rfc4941);

/*****************************************************************************/

int nm_l3_config_data_get_ifindex (const NML3ConfigData *self);

static inline gboolean
NM_IS_L3_CONFIG_DATA (const NML3ConfigData *self)
{
	/* NML3ConfigData is not an NMObject, so we cannot ask which type it has.
	 * This check here is really only useful for assertions, and there it is
	 * enough to check whether the pointer is not NULL.
	 *
	 * Additionally, also call nm_l3_config_data_get_ifindex(), which does more
	 * checks during nm_assert(). */
	nm_assert (nm_l3_config_data_get_ifindex (self) > 0);
	return !!self;
}

/*****************************************************************************/

int nm_l3_config_data_cmp (const NML3ConfigData *a, const NML3ConfigData *b);

static inline gboolean
nm_l3_config_data_equal (const NML3ConfigData *a, const NML3ConfigData *b)
{
	return nm_l3_config_data_cmp (a, b) == 0;
}

/*****************************************************************************/

const NMDedupMultiHeadEntry *nm_l3_config_data_lookup_objs (const NML3ConfigData *self, NMPObjectType obj_type);

static inline const NMDedupMultiHeadEntry *
nm_l3_config_data_lookup_addresses (const NML3ConfigData *self, int addr_family)
{
	nm_assert_addr_family (addr_family);

	return nm_l3_config_data_lookup_objs (self,
	                                        addr_family == AF_INET
	                                      ? NMP_OBJECT_TYPE_IP4_ADDRESS
	                                      : NMP_OBJECT_TYPE_IP6_ADDRESS);
}

static inline const NMDedupMultiHeadEntry *
nm_l3_config_data_lookup_routes (const NML3ConfigData *self, int addr_family)
{
	nm_assert_addr_family (addr_family);

	return nm_l3_config_data_lookup_objs (self,
	                                        addr_family == AF_INET
	                                      ? NMP_OBJECT_TYPE_IP4_ROUTE
	                                      : NMP_OBJECT_TYPE_IP6_ROUTE);
}

#define nm_l3_config_data_iter_obj_for_each(iter, self, obj, type) \
    for (nm_dedup_multi_iter_init (&(iter), nm_l3_config_data_lookup_objs ((self), (type))); \
         nm_platform_dedup_multi_iter_next_obj (&(iter), &(obj), (type)); \
         )

#define nm_l3_config_data_iter_ip4_address_for_each(iter, self, address) \
    for (nm_dedup_multi_iter_init (&(iter), nm_l3_config_data_lookup_addresses ((self), AF_INET)); \
         nm_platform_dedup_multi_iter_next_ip4_address (&(iter), &(address)); \
         )

#define nm_l3_config_data_iter_ip6_address_for_each(iter, self, address) \
    for (nm_dedup_multi_iter_init (&(iter), nm_l3_config_data_lookup_addresses ((self), AF_INET6)); \
         nm_platform_dedup_multi_iter_next_ip6_address (&(iter), &(address)); \
         )

#define nm_l3_config_data_iter_ip4_route_for_each(iter, self, route) \
    for (nm_dedup_multi_iter_init (&(iter), nm_l3_config_data_lookup_routes ((self), AF_INET)); \
         nm_platform_dedup_multi_iter_next_ip4_route  (&(iter), &(route)); \
         )

#define nm_l3_config_data_iter_ip6_route_for_each(iter, self, route) \
    for (nm_dedup_multi_iter_init (&(iter), nm_l3_config_data_lookup_routes ((self), AF_INET6)); \
         nm_platform_dedup_multi_iter_next_ip6_route  (&(iter), &(route)); \
         )

/*****************************************************************************/

NML3ConfigDatFlags nm_l3_config_data_get_flags (const NML3ConfigData *self);

void nm_l3_config_data_set_flags_full (NML3ConfigData *self,
                                       NML3ConfigDatFlags flags,
                                       NML3ConfigDatFlags mask);

static inline void
nm_l3_config_data_set_flags (NML3ConfigData *self,
                             NML3ConfigDatFlags flags)
{
	nm_l3_config_data_set_flags_full (self, flags, flags);
}

static inline void
nm_l3_config_data_unset_flags (NML3ConfigData *self,
                               NML3ConfigDatFlags flags)
{
	nm_l3_config_data_set_flags_full (self, NM_L3_CONFIG_DAT_FLAGS_NONE, flags);
}

/*****************************************************************************/

gboolean nm_l3_config_data_add_address_full (NML3ConfigData *self,
                                             int addr_family,
                                             const NMPObject *obj_new,
                                             const NMPlatformIPAddress *pl_new,
                                             NML3ConfigAddFlags add_flags,
                                             const NMPObject **out_obj_new);

static inline gboolean
nm_l3_config_data_add_address (NML3ConfigData *self,
                               int addr_family,
                               const NMPObject *obj_new,
                               const NMPlatformIPAddress *pl_new)
{
	return nm_l3_config_data_add_address_full (self,
	                                           addr_family,
	                                           obj_new,
	                                           pl_new,
	                                           NM_L3_CONFIG_ADD_FLAGS_MERGE,
	                                           NULL);
}

static inline gboolean
nm_l3_config_data_add_address_4 (NML3ConfigData *self, const NMPlatformIP4Address *addr)
{
	return nm_l3_config_data_add_address (self, AF_INET, NULL, NM_PLATFORM_IP_ADDRESS_CAST (addr));
}

static inline gboolean
nm_l3_config_data_add_address_6 (NML3ConfigData *self, const NMPlatformIP6Address *addr)
{
	return nm_l3_config_data_add_address (self, AF_INET6, NULL, NM_PLATFORM_IP_ADDRESS_CAST (addr));
}

gboolean nm_l3_config_data_add_route_full (NML3ConfigData *self,
                                           int addr_family,
                                           const NMPObject *obj_new,
                                           const NMPlatformIPRoute *pl_new,
                                           NML3ConfigAddFlags add_flags,
                                           const NMPObject **out_obj_new,
                                           gboolean *out_changed_best_default_route);

static inline gboolean
nm_l3_config_data_add_route (NML3ConfigData *self,
                             int addr_family,
                             const NMPObject *obj_new,
                             const NMPlatformIPRoute *pl_new)
{
	return nm_l3_config_data_add_route_full (self,
	                                         addr_family,
	                                         obj_new,
	                                         pl_new,
	                                         NM_L3_CONFIG_ADD_FLAGS_MERGE,
	                                         NULL,
	                                         NULL);
}

static inline gboolean
nm_l3_config_data_add_route_4 (NML3ConfigData *self, const NMPlatformIP4Route *rt)
{
	return nm_l3_config_data_add_route (self, AF_INET, NULL, NM_PLATFORM_IP_ROUTE_CAST (rt));
}

static inline gboolean
nm_l3_config_data_add_route_6 (NML3ConfigData *self, const NMPlatformIP6Route *rt)
{
	return nm_l3_config_data_add_route (self, AF_INET6, NULL, NM_PLATFORM_IP_ROUTE_CAST (rt));
}

gboolean nm_l3_config_data_add_nameserver (NML3ConfigData *self,
                                           int addr_family,
                                           gconstpointer /* (const NMIPAddr *) */ nameserver);

gboolean nm_l3_config_data_add_wins (NML3ConfigData *self,
                                     in_addr_t wins);

gboolean nm_l3_config_data_add_domain (NML3ConfigData *self,
                                       int addr_family,
                                       const char *domain);

gboolean nm_l3_config_data_add_search (NML3ConfigData *self,
                                       int addr_family,
                                       const char *search);

gboolean nm_l3_config_data_add_dns_option (NML3ConfigData *self,
                                           int addr_family,
                                           const char *dns_option);

gboolean nm_l3_config_data_set_dns_priority (NML3ConfigData *self,
                                             int addr_family,
                                             int dns_priority);

#endif /* __NM_L3_CONFIG_DATA_H__ */
