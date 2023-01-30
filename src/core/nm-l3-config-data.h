/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_L3_CONFIG_DATA_H__
#define __NM_L3_CONFIG_DATA_H__

#include "libnm-glib-aux/nm-dedup-multi.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip6-config.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-object.h"

typedef enum {
    NM_PROXY_CONFIG_METHOD_UNKNOWN,
    NM_PROXY_CONFIG_METHOD_NONE,
    NM_PROXY_CONFIG_METHOD_AUTO,
} NMProxyConfigMethod;

typedef enum {
    NM_L3_CONFIG_DAT_FLAGS_NONE = 0,

    /* if set, then the merge flag NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES gets
     * ignored during merge. */
    NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES = (1ull << 0),

    NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_4 = (1ull << 1),
    NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_6 = (1ull << 2),
#define NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY(is_ipv4)   \
    ((is_ipv4) ? NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_4 \
               : NM_L3_CONFIG_DAT_FLAGS_HAS_DNS_PRIORITY_6)

} NML3ConfigDatFlags;

typedef enum {
    NM_L3_CONFIG_ADD_FLAGS_NONE = 0,

    /* If the object does not yet exist, it will be added. If it already exists,
     * by default the object will be replaced. With this flag, the new object will
     * be merged with the existing one. */
    NM_L3_CONFIG_ADD_FLAGS_MERGE = (1ull << 0),

    /* If the object does not yet exist, it will be added. If it already exists,
     * by default the object will be replaced. With this flag, the add will have
     * no effect and the existing object will be kept. */
    NM_L3_CONFIG_ADD_FLAGS_EXCLUSIVE = (1ull << 1),

    /* A new object gets appended by default. If the object already exists,
     * by default it will not be moved. With APPEND-FORCE, we will always move
     * an existing object to the end of the list. */
    NM_L3_CONFIG_ADD_FLAGS_APPEND_FORCE = (1ull << 2),
} NML3ConfigAddFlags;

/**
 * NML3ConfigMergeFlags:
 * @NM_L3_CONFIG_MERGE_FLAGS_NONE: no flags set
 * @NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES: don't merge routes
 * @NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES: don't merge default routes.
 *   Note that if the respective NML3ConfigData has NM_L3_CONFIG_DAT_FLAGS_IGNORE_MERGE_NO_DEFAULT_ROUTES
 *   set, this flag gets ignored during merge.
 * @NM_L3_CONFIG_MERGE_FLAGS_NO_DNS: don't merge DNS information
 * @NM_L3_CONFIG_MERGE_FLAGS_CLONE: clone is also implemented via "merge".
 *   In that case, it takes all settings.
 */
typedef enum _nm_packed {
    NM_L3_CONFIG_MERGE_FLAGS_NONE              = 0,
    NM_L3_CONFIG_MERGE_FLAGS_NO_ROUTES         = (1LL << 0),
    NM_L3_CONFIG_MERGE_FLAGS_NO_DEFAULT_ROUTES = (1LL << 1),
    NM_L3_CONFIG_MERGE_FLAGS_NO_DNS            = (1LL << 2),
    NM_L3_CONFIG_MERGE_FLAGS_CLONE             = (1LL << 3),
} NML3ConfigMergeFlags;

/*****************************************************************************/

static inline gboolean NM_IS_L3_CONFIG_DATA(const NML3ConfigData *self);

NML3ConfigData *
nm_l3_config_data_new(NMDedupMultiIndex *multi_idx, int ifindex, NMIPConfigSource source);
const NML3ConfigData *nm_l3_config_data_ref(const NML3ConfigData *self);
const NML3ConfigData *nm_l3_config_data_ref_and_seal(const NML3ConfigData *self);
const NML3ConfigData *nm_l3_config_data_seal(const NML3ConfigData *self);
void                  nm_l3_config_data_unref(const NML3ConfigData *self);

#define nm_clear_l3cd(ptr) nm_clear_pointer((ptr), nm_l3_config_data_unref)

NM_AUTO_DEFINE_FCN0(const NML3ConfigData *, _nm_auto_unref_l3cd, nm_l3_config_data_unref);
#define nm_auto_unref_l3cd nm_auto(_nm_auto_unref_l3cd)

NM_AUTO_DEFINE_FCN0(NML3ConfigData *, _nm_auto_unref_l3cd_init, nm_l3_config_data_unref);
#define nm_auto_unref_l3cd_init nm_auto(_nm_auto_unref_l3cd_init)

static inline gboolean
nm_l3_config_data_reset(const NML3ConfigData **dst, const NML3ConfigData *src)
{
    nm_auto_unref_l3cd const NML3ConfigData *old = NULL;

    nm_assert(dst);
    nm_assert(!*dst || NM_IS_L3_CONFIG_DATA(*dst));
    nm_assert(!src || NM_IS_L3_CONFIG_DATA(src));

    if (*dst == src)
        return FALSE;
    old  = *dst;
    *dst = src ? nm_l3_config_data_ref_and_seal(src) : NULL;
    return TRUE;
}

static inline gboolean
nm_l3_config_data_reset_take(const NML3ConfigData **dst, const NML3ConfigData *src)
{
    nm_auto_unref_l3cd const NML3ConfigData *old = NULL;

    nm_assert(dst);
    nm_assert(!*dst || NM_IS_L3_CONFIG_DATA(*dst));
    nm_assert(!src || NM_IS_L3_CONFIG_DATA(src));

    if (*dst == src) {
        if (src)
            nm_l3_config_data_unref(src);
        return FALSE;
    }
    old  = *dst;
    *dst = src ? nm_l3_config_data_seal(src) : NULL;
    return TRUE;
}

gboolean nm_l3_config_data_is_sealed(const NML3ConfigData *self);

NML3ConfigData *nm_l3_config_data_new_clone(const NML3ConfigData *src, int ifindex);

NML3ConfigData *nm_l3_config_data_new_from_connection(NMDedupMultiIndex *multi_idx,
                                                      int                ifindex,
                                                      NMConnection      *connection);

NML3ConfigData *nm_l3_config_data_new_from_platform(NMDedupMultiIndex        *multi_idx,
                                                    int                       ifindex,
                                                    NMPlatform               *platform,
                                                    NMSettingIP6ConfigPrivacy ipv6_privacy_rfc4941);

typedef struct {
    NMOptionBool ip4acd_not_ready;
    NMOptionBool force_commit;
} NML3ConfigMergeHookResult;

typedef gboolean (*NML3ConfigMergeHookAddObj)(const NML3ConfigData      *l3cd,
                                              const NMPObject           *obj,
                                              NML3ConfigMergeHookResult *result,
                                              gpointer                   user_data);

void nm_l3_config_data_merge(NML3ConfigData       *self,
                             const NML3ConfigData *src,
                             NML3ConfigMergeFlags  merge_flags,
                             const guint32 *default_route_table_x /* length 2, for IS_IPv4 */,
                             const guint32 *default_route_metric_x /* length 2, for IS_IPv4 */,
                             const guint32 *default_route_penalty_x /* length 2, for IS_IPv4 */,
                             const int     *default_dns_priority_x /* length 2, for IS_IPv4 */,
                             NML3ConfigMergeHookAddObj hook_add_obj,
                             gpointer                  hook_user_data);

GPtrArray *nm_l3_config_data_get_blacklisted_ip4_routes(const NML3ConfigData *self,
                                                        gboolean              is_vrf);

void nm_l3_config_data_add_dependent_onlink_routes(NML3ConfigData *self, int addr_family);

void nm_l3_config_data_add_dependent_device_routes(NML3ConfigData       *self,
                                                   int                   addr_family,
                                                   guint32               route_table,
                                                   guint32               route_metric,
                                                   gboolean              force_commit,
                                                   const NML3ConfigData *source);

/*****************************************************************************/

void nm_l3_config_data_log(const NML3ConfigData *self,
                           const char           *title,
                           const char           *prefix,
                           NMLogLevel            log_level,
                           NMLogDomain           log_domain);

/*****************************************************************************/

int nm_l3_config_data_get_ifindex(const NML3ConfigData *self);

static inline gboolean
NM_IS_L3_CONFIG_DATA(const NML3ConfigData *self)
{
    /* NML3ConfigData is not an NMObject/GObject, so we cannot ask which type it has.
     * This check here is really only useful for assertions, and there it is
     * enough to check whether the pointer is not NULL.
     *
     * Additionally, also call nm_l3_config_data_get_ifindex(), which does more
     * checks during nm_assert(). */
    nm_assert(!self || nm_l3_config_data_get_ifindex(self) > 0);
    return !!self;
}

NMDedupMultiIndex *nm_l3_config_data_get_multi_idx(const NML3ConfigData *self);

/*****************************************************************************/

typedef enum {
    NM_L3_CONFIG_CMP_FLAGS_NONE         = 0,
    NM_L3_CONFIG_CMP_FLAGS_IFINDEX      = (1LL << 0),
    NM_L3_CONFIG_CMP_FLAGS_ADDRESSES_ID = (1LL << 1),
    NM_L3_CONFIG_CMP_FLAGS_ADDRESSES    = (1LL << 2),
    NM_L3_CONFIG_CMP_FLAGS_ROUTES_ID    = (1LL << 3),
    NM_L3_CONFIG_CMP_FLAGS_ROUTES       = (1LL << 4),
    NM_L3_CONFIG_CMP_FLAGS_DNS          = (1LL << 5),
    NM_L3_CONFIG_CMP_FLAGS_OTHER        = (1LL << 6),
    NM_L3_CONFIG_CMP_FLAGS_ALL          = (1LL << 7) - 1,
} NML3ConfigCmpFlags;

int nm_l3_config_data_cmp_full(const NML3ConfigData *a,
                               const NML3ConfigData *b,
                               NML3ConfigCmpFlags    flags);

static inline int
nm_l3_config_data_cmp(const NML3ConfigData *a, const NML3ConfigData *b)
{
    return nm_l3_config_data_cmp_full(a, b, NM_L3_CONFIG_CMP_FLAGS_ALL);
}

static inline gboolean
nm_l3_config_data_equal(const NML3ConfigData *a, const NML3ConfigData *b)
{
    return nm_l3_config_data_cmp(a, b) == 0;
}

/*****************************************************************************/

const NMDedupMultiIdxType *nm_l3_config_data_lookup_index(const NML3ConfigData *self,
                                                          NMPObjectType         obj_type);

const NMDedupMultiEntry *nm_l3_config_data_lookup_obj(const NML3ConfigData *self,
                                                      const NMPObject      *obj);

const NMPlatformIP4Address *nm_l3_config_data_lookup_address_4(const NML3ConfigData *self,
                                                               in_addr_t             addr,
                                                               guint8                plen,
                                                               in_addr_t             peer_addr);

const NMPlatformIP6Address *nm_l3_config_data_lookup_address_6(const NML3ConfigData  *self,
                                                               const struct in6_addr *addr);

const NMDedupMultiEntry *nm_l3_config_data_lookup_route_obj(const NML3ConfigData *self,
                                                            const NMPObject      *needle);

const NMDedupMultiEntry *nm_l3_config_data_lookup_route(const NML3ConfigData    *self,
                                                        int                      addr_family,
                                                        const NMPlatformIPRoute *needle);

const NMDedupMultiHeadEntry *nm_l3_config_data_lookup_objs(const NML3ConfigData *self,
                                                           NMPObjectType         obj_type);

static inline const NMDedupMultiHeadEntry *
nm_l3_config_data_lookup_addresses(const NML3ConfigData *self, int addr_family)
{
    return nm_l3_config_data_lookup_objs(self, NMP_OBJECT_TYPE_IP_ADDRESS(NM_IS_IPv4(addr_family)));
}

static inline const NMDedupMultiHeadEntry *
nm_l3_config_data_lookup_routes(const NML3ConfigData *self, int addr_family)
{
    return nm_l3_config_data_lookup_objs(self, NMP_OBJECT_TYPE_IP_ROUTE(NM_IS_IPv4(addr_family)));
}

#define nm_l3_config_data_iter_obj_for_each(iter, self, obj, type)                        \
    for (nm_dedup_multi_iter_init((iter), nm_l3_config_data_lookup_objs((self), (type))); \
         nm_platform_dedup_multi_iter_next_obj((iter), (obj), (type));)

#define nm_l3_config_data_iter_ip_address_for_each(iter, self, addr_family, address)          \
    for (nm_dedup_multi_iter_init((iter),                                                     \
                                  nm_l3_config_data_lookup_addresses((self), (addr_family))); \
         nm_platform_dedup_multi_iter_next_ip_address((iter), (address));)

#define nm_l3_config_data_iter_ip4_address_for_each(iter, self, address)                        \
    for (nm_dedup_multi_iter_init((iter), nm_l3_config_data_lookup_addresses((self), AF_INET)); \
         nm_platform_dedup_multi_iter_next_ip4_address((iter), (address));)

#define nm_l3_config_data_iter_ip6_address_for_each(iter, self, address)                         \
    for (nm_dedup_multi_iter_init((iter), nm_l3_config_data_lookup_addresses((self), AF_INET6)); \
         nm_platform_dedup_multi_iter_next_ip6_address((iter), (address));)

#define nm_l3_config_data_iter_ip_route_for_each(iter, self, addr_family, route)                   \
    for (nm_dedup_multi_iter_init((iter), nm_l3_config_data_lookup_routes((self), (addr_family))); \
         nm_platform_dedup_multi_iter_next_ip_route((iter), (route));)

#define nm_l3_config_data_iter_ip4_route_for_each(iter, self, route)                         \
    for (nm_dedup_multi_iter_init((iter), nm_l3_config_data_lookup_routes((self), AF_INET)); \
         nm_platform_dedup_multi_iter_next_ip4_route((iter), (route));)

#define nm_l3_config_data_iter_ip6_route_for_each(iter, self, route)                          \
    for (nm_dedup_multi_iter_init((iter), nm_l3_config_data_lookup_routes((self), AF_INET6)); \
         nm_platform_dedup_multi_iter_next_ip6_route((iter), (route));)

static inline guint
nm_l3_config_data_get_num_objs(const NML3ConfigData *self, NMPObjectType obj_type)
{
    const NMDedupMultiHeadEntry *head_entry;

    head_entry = nm_l3_config_data_lookup_objs(self, obj_type);
    return head_entry ? head_entry->len : 0u;
}

static inline guint
nm_l3_config_data_get_num_addresses(const NML3ConfigData *self, int addr_family)
{
    return nm_l3_config_data_get_num_objs(self,
                                          NM_IS_IPv4(addr_family) ? NMP_OBJECT_TYPE_IP4_ADDRESS
                                                                  : NMP_OBJECT_TYPE_IP6_ADDRESS);
}

static inline guint
nm_l3_config_data_get_num_routes(const NML3ConfigData *self, int addr_family)
{
    return nm_l3_config_data_get_num_objs(self,
                                          NM_IS_IPv4(addr_family) ? NMP_OBJECT_TYPE_IP4_ROUTE
                                                                  : NMP_OBJECT_TYPE_IP6_ROUTE);
}

gboolean nm_l3_config_data_has_routes_with_type_local(const NML3ConfigData *self, int addr_family);

const NMPObject *
nmtst_l3_config_data_get_obj_at(const NML3ConfigData *self, NMPObjectType obj_type, guint i);

static inline const NMPlatformIP4Address *
nmtst_l3_config_data_get_address_at_4(const NML3ConfigData *self, guint i)
{
    return NMP_OBJECT_CAST_IP4_ADDRESS(
        nmtst_l3_config_data_get_obj_at(self, NMP_OBJECT_TYPE_IP4_ADDRESS, i));
}

static inline const NMPlatformIP6Address *
nmtst_l3_config_data_get_address_at_6(const NML3ConfigData *self, guint i)
{
    return NMP_OBJECT_CAST_IP6_ADDRESS(
        nmtst_l3_config_data_get_obj_at(self, NMP_OBJECT_TYPE_IP6_ADDRESS, i));
}

static inline const NMPlatformIP4Route *
nmtst_l3_config_data_get_route_at_4(const NML3ConfigData *self, guint i)
{
    return NMP_OBJECT_CAST_IP4_ROUTE(
        nmtst_l3_config_data_get_obj_at(self, NMP_OBJECT_TYPE_IP4_ROUTE, i));
}

static inline const NMPlatformIP6Route *
nmtst_l3_config_data_get_route_at_6(const NML3ConfigData *self, guint i)
{
    return NMP_OBJECT_CAST_IP6_ROUTE(
        nmtst_l3_config_data_get_obj_at(self, NMP_OBJECT_TYPE_IP6_ROUTE, i));
}

/*****************************************************************************/

NML3ConfigDatFlags nm_l3_config_data_get_flags(const NML3ConfigData *self);

void nm_l3_config_data_set_flags_full(NML3ConfigData    *self,
                                      NML3ConfigDatFlags flags,
                                      NML3ConfigDatFlags mask);

static inline void
nm_l3_config_data_set_flags(NML3ConfigData *self, NML3ConfigDatFlags flags)
{
    nm_l3_config_data_set_flags_full(self, flags, flags);
}

static inline void
nm_l3_config_data_unset_flags(NML3ConfigData *self, NML3ConfigDatFlags flags)
{
    nm_l3_config_data_set_flags_full(self, NM_L3_CONFIG_DAT_FLAGS_NONE, flags);
}

/*****************************************************************************/

const NMPObject *nm_l3_config_data_get_first_obj(const NML3ConfigData *self,
                                                 NMPObjectType         obj_type,
                                                 gboolean (*predicate)(const NMPObject *obj));

gboolean nm_l3_config_data_add_address_full(NML3ConfigData            *self,
                                            int                        addr_family,
                                            const NMPObject           *obj_new,
                                            const NMPlatformIPAddress *pl_new,
                                            NML3ConfigAddFlags         add_flags,
                                            const NMPObject          **out_obj_new);

static inline gboolean
nm_l3_config_data_add_address(NML3ConfigData            *self,
                              int                        addr_family,
                              const NMPObject           *obj_new,
                              const NMPlatformIPAddress *pl_new)
{
    return nm_l3_config_data_add_address_full(self,
                                              addr_family,
                                              obj_new,
                                              pl_new,
                                              NM_L3_CONFIG_ADD_FLAGS_MERGE,
                                              NULL);
}

static inline gboolean
nm_l3_config_data_add_address_4(NML3ConfigData *self, const NMPlatformIP4Address *addr)
{
    return nm_l3_config_data_add_address(self, AF_INET, NULL, NM_PLATFORM_IP_ADDRESS_CAST(addr));
}

static inline gboolean
nm_l3_config_data_add_address_6(NML3ConfigData *self, const NMPlatformIP6Address *addr)
{
    return nm_l3_config_data_add_address(self, AF_INET6, NULL, NM_PLATFORM_IP_ADDRESS_CAST(addr));
}

gboolean nm_l3_config_data_add_route_full(NML3ConfigData          *self,
                                          int                      addr_family,
                                          const NMPObject         *obj_new,
                                          const NMPlatformIPRoute *pl_new,
                                          NML3ConfigAddFlags       add_flags,
                                          const NMPObject        **out_obj_new,
                                          gboolean                *out_changed_best_default_route);

static inline gboolean
nm_l3_config_data_add_route(NML3ConfigData          *self,
                            int                      addr_family,
                            const NMPObject         *obj_new,
                            const NMPlatformIPRoute *pl_new)
{
    return nm_l3_config_data_add_route_full(self,
                                            addr_family,
                                            obj_new,
                                            pl_new,
                                            NM_L3_CONFIG_ADD_FLAGS_MERGE,
                                            NULL,
                                            NULL);
}

static inline gboolean
nm_l3_config_data_add_route_4(NML3ConfigData *self, const NMPlatformIP4Route *rt)
{
    return nm_l3_config_data_add_route(self, AF_INET, NULL, NM_PLATFORM_IP_ROUTE_CAST(rt));
}

static inline gboolean
nm_l3_config_data_add_route_6(NML3ConfigData *self, const NMPlatformIP6Route *rt)
{
    return nm_l3_config_data_add_route(self, AF_INET6, NULL, NM_PLATFORM_IP_ROUTE_CAST(rt));
}

const NMPObject *nm_l3_config_data_get_best_default_route(const NML3ConfigData *self,
                                                          int                   addr_family);

NMSettingConnectionMdns nm_l3_config_data_get_mdns(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_mdns(NML3ConfigData *self, NMSettingConnectionMdns mdns);

NMSettingConnectionLlmnr nm_l3_config_data_get_llmnr(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_llmnr(NML3ConfigData *self, NMSettingConnectionLlmnr llmnr);

NMSettingConnectionDnsOverTls nm_l3_config_data_get_dns_over_tls(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_dns_over_tls(NML3ConfigData               *self,
                                            NMSettingConnectionDnsOverTls dns_over_tls);

NMIPRouteTableSyncMode nm_l3_config_data_get_route_table_sync(const NML3ConfigData *self,
                                                              int                   addr_family);

gboolean nm_l3_config_data_set_route_table_sync(NML3ConfigData        *self,
                                                int                    addr_family,
                                                NMIPRouteTableSyncMode route_table_sync);

NMTernary nm_l3_config_data_get_never_default(const NML3ConfigData *self, int addr_family);

gboolean
nm_l3_config_data_set_never_default(NML3ConfigData *self, int addr_family, NMTernary never_default);

NMTernary nm_l3_config_data_get_metered(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_metered(NML3ConfigData *self, NMTernary metered);

guint32 nm_l3_config_data_get_mtu(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_mtu(NML3ConfigData *self, guint32 mtu);

guint32 nm_l3_config_data_get_ip6_mtu(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_ip6_mtu(NML3ConfigData *self, guint32 ip6_mtu);

NMUtilsIPv6IfaceId nm_l3_config_data_get_ip6_token(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_ip6_token(NML3ConfigData *self, NMUtilsIPv6IfaceId ipv6_token);

NMMptcpFlags nm_l3_config_data_get_mptcp_flags(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_mptcp_flags(NML3ConfigData *self, NMMptcpFlags mptcp_flags);

const in_addr_t *nm_l3_config_data_get_wins(const NML3ConfigData *self, guint *out_len);

gboolean nm_l3_config_data_add_wins(NML3ConfigData *self, in_addr_t wins);

const char *const *
nm_l3_config_data_get_nameservers(const NML3ConfigData *self, int addr_family, guint *out_len);

gboolean
nm_l3_config_data_add_nameserver(NML3ConfigData *self, int addr_family, const char *nameserver);

gboolean nm_l3_config_data_add_nameserver_detail(NML3ConfigData *self,
                                                 int             addr_family,
                                                 gconstpointer   addr_bin,
                                                 const char     *server_name);

gboolean nm_l3_config_data_clear_nameservers(NML3ConfigData *self, int addr_family);

const in_addr_t *nm_l3_config_data_get_nis_servers(const NML3ConfigData *self, guint *out_len);

gboolean nm_l3_config_data_add_nis_server(NML3ConfigData *self, in_addr_t nis_server);

const char *nm_l3_config_data_get_nis_domain(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_nis_domain(NML3ConfigData *self, const char *nis_domain);

const char *const *
nm_l3_config_data_get_domains(const NML3ConfigData *self, int addr_family, guint *out_len);

gboolean nm_l3_config_data_add_domain(NML3ConfigData *self, int addr_family, const char *domain);

const char *const *
nm_l3_config_data_get_searches(const NML3ConfigData *self, int addr_family, guint *out_len);

gboolean nm_l3_config_data_clear_searches(NML3ConfigData *self, int addr_family);

gboolean nm_l3_config_data_add_search(NML3ConfigData *self, int addr_family, const char *search);

gboolean
nm_l3_config_data_add_dns_option(NML3ConfigData *self, int addr_family, const char *dns_option);

const char *const *
nm_l3_config_data_get_dns_options(const NML3ConfigData *self, int addr_family, guint *out_len);

gboolean
nm_l3_config_data_get_dns_priority(const NML3ConfigData *self, int addr_family, int *out_prio);

static inline int
nm_l3_config_data_get_dns_priority_or_default(const NML3ConfigData *self, int addr_family)
{
    int v;

    nm_assert_addr_family(addr_family);
    if (!self || !nm_l3_config_data_get_dns_priority(self, addr_family, &v))
        return 0;
    return v;
}

gboolean
nm_l3_config_data_set_dns_priority(NML3ConfigData *self, int addr_family, int dns_priority);

NMSettingIP6ConfigPrivacy nm_l3_config_data_get_ip6_privacy(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_ip6_privacy(NML3ConfigData           *self,
                                           NMSettingIP6ConfigPrivacy ip6_privacy);

NMProxyConfigMethod nm_l3_config_data_get_proxy_method(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_proxy_method(NML3ConfigData *self, NMProxyConfigMethod value);

NMTernary nm_l3_config_data_get_proxy_browser_only(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_proxy_browser_only(NML3ConfigData *self, NMTernary value);

const char *nm_l3_config_data_get_proxy_pac_url(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_proxy_pac_url(NML3ConfigData *self, const char *value);

const char *nm_l3_config_data_get_proxy_pac_script(const NML3ConfigData *self);

gboolean nm_l3_config_data_set_proxy_pac_script(NML3ConfigData *self, const char *value);

gboolean nm_l3_config_data_get_ndisc_hop_limit(const NML3ConfigData *self, int *out_val);
gboolean nm_l3_config_data_set_ndisc_hop_limit(NML3ConfigData *self, int val);

gboolean nm_l3_config_data_get_ndisc_reachable_time_msec(const NML3ConfigData *self,
                                                         guint32              *out_val);
gboolean nm_l3_config_data_set_ndisc_reachable_time_msec(NML3ConfigData *self, guint32 val);

gboolean nm_l3_config_data_get_ndisc_retrans_timer_msec(const NML3ConfigData *self,
                                                        guint32              *out_val);
gboolean nm_l3_config_data_set_ndisc_retrans_timer_msec(NML3ConfigData *self, guint32 val);

struct _NMDhcpLease *nm_l3_config_data_get_dhcp_lease(const NML3ConfigData *self, int addr_family);

gboolean
nm_l3_config_data_set_dhcp_lease(NML3ConfigData *self, int addr_family, struct _NMDhcpLease *lease);

gboolean nm_l3_config_data_set_dhcp_lease_from_options(NML3ConfigData *self,
                                                       int             addr_family,
                                                       GHashTable     *options_take);

static inline const NMIPAddr *
nmtst_l3_config_data_get_best_gateway(const NML3ConfigData *self, int addr_family)
{
    const NMPObject *rt;

    rt = nm_l3_config_data_get_best_default_route(self, addr_family);
    if (!rt)
        return NULL;

    return nm_platform_ip_route_get_gateway(addr_family, NMP_OBJECT_CAST_IP_ROUTE(rt));
}

void nm_l3_config_data_hash_dns(const NML3ConfigData *l3cd,
                                GChecksum            *sum,
                                int                   addr_family,
                                NMDnsIPConfigType     dns_ip_config_type);

#endif /* __NM_L3_CONFIG_DATA_H__ */
