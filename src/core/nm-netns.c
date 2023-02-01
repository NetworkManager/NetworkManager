/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-netns.h"

#include <linux/rtnetlink.h>

#include "libnm-glib-aux/nm-dedup-multi.h"
#include "libnm-glib-aux/nm-c-list.h"

#include "NetworkManagerUtils.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "nm-l3cfg.h"
#include "libnm-platform/nm-platform.h"
#include "libnm-platform/nmp-netns.h"
#include "libnm-platform/nmp-global-tracker.h"
#include "libnm-std-aux/c-list-util.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PLATFORM, );

typedef struct {
    NMNetns          *_self_signal_user_data;
    NMPlatform       *platform;
    NMPNetns         *platform_netns;
    NMPGlobalTracker *global_tracker;
    GHashTable       *l3cfgs;
    GHashTable       *shared_ips;
    GHashTable       *ecmp_track_by_obj;
    GHashTable       *ecmp_track_by_ecmpid;
    CList             l3cfg_signal_pending_lst_head;
    GSource          *signal_pending_idle_source;
} NMNetnsPrivate;

struct _NMNetns {
    GObject        parent;
    NMNetnsPrivate _priv;
};

struct _NMNetnsClass {
    GObjectClass parent;
};

G_DEFINE_TYPE(NMNetns, nm_netns, G_TYPE_OBJECT);

#define NM_NETNS_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMNetns, NM_IS_NETNS)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG_PREFIX_NAME "netns"
#define _NMLOG(level, ...)                                                                  \
    G_STMT_START                                                                            \
    {                                                                                       \
        nm_log((level),                                                                     \
               (_NMLOG_DOMAIN),                                                             \
               NULL,                                                                        \
               NULL,                                                                        \
               "netns[" NM_HASH_OBFUSCATE_PTR_FMT "]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
               NM_HASH_OBFUSCATE_PTR(self) _NM_UTILS_MACRO_REST(__VA_ARGS__));              \
    }                                                                                       \
    G_STMT_END

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER(NMNetns, nm_netns_get, NM_TYPE_NETNS);

/*****************************************************************************/

#define nm_assert_l3cfg(self, l3cfg)                                                      \
    G_STMT_START                                                                          \
    {                                                                                     \
        NMNetns *_self  = (self);                                                         \
        NML3Cfg *_l3cfg = (l3cfg);                                                        \
                                                                                          \
        nm_assert(NM_IS_NETNS(self));                                                     \
        nm_assert(NM_IS_L3CFG(_l3cfg));                                                   \
        if (NM_MORE_ASSERTS > 5)                                                          \
            nm_assert(_l3cfg == nm_netns_l3cfg_get(_self, nm_l3cfg_get_ifindex(_l3cfg))); \
    }                                                                                     \
    G_STMT_END

/*****************************************************************************/

typedef struct {
    const NMPObject *representative_obj;
    const NMPObject *merged_obj;
    CList            ecmpid_lst_head;
    bool             needs_update : 1;
    bool             already_visited : 1;
} EcmpTrackEcmpid;

typedef struct {
    const NMPObject *obj;

    NML3Cfg         *l3cfg;
    EcmpTrackEcmpid *parent_track_ecmpid;

    CList ifindex_lst;
    CList ecmpid_lst;

    /* Calling nm_netns_ip_route_ecmp_register() will ensure that the tracked
     * entry is non-dirty. This can be used to remove stale entries. */
    bool dirty : 1;

    /* This flag is set during nm_netns_ip_route_ecmp_register(), when first tracking the
     * route. It is cleared on the next nm_netns_ip_route_ecmp_commit(). It thus only
     * exists for a short time, to know during a commit that the route is new and
     * we need to do something special. */
    bool is_new : 1;

    /* The entry is ready to be configured. This exists, because the nexthop of
     * a route must be reachable directly (being onlink). That is, we may need
     * to add a direct, single-hop route to the gateway, which is done by
     * the NML3Cfg of that interface. Since the NML3Cfg calls nm_netns_ip_route_ecmp_commit()
     * and only adds the direct route afterwards, the ECMP route may not be ready
     * right away, but only upon seeing the entry a second time. */
    bool is_ready : 1;
} EcmpTrackObj;

static int
_ecmp_track_sort_lst_cmp(const CList *a, const CList *b, const void *user_data)
{
    EcmpTrackObj             *track_obj_a = c_list_entry(a, EcmpTrackObj, ecmpid_lst);
    EcmpTrackObj             *track_obj_b = c_list_entry(b, EcmpTrackObj, ecmpid_lst);
    const NMPlatformIP4Route *route_a     = NMP_OBJECT_CAST_IP4_ROUTE(track_obj_a->obj);
    const NMPlatformIP4Route *route_b     = NMP_OBJECT_CAST_IP4_ROUTE(track_obj_b->obj);

    nm_assert(route_a->ifindex > 0);
    nm_assert(route_a->n_nexthops <= 1);
    nm_assert(route_b->ifindex > 0);
    nm_assert(route_b->n_nexthops <= 1);

    NM_CMP_FIELD(route_a, route_b, ifindex);
    NM_CMP_FIELD(route_b, route_a, weight);
    NM_CMP_DIRECT(htonl(route_a->gateway), htonl(route_b->gateway));

    return nm_assert_unreachable_val(
        nm_platform_ip4_route_cmp(route_a, route_b, NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID));
}

static gboolean
_ecmp_track_init_merged_obj(EcmpTrackEcmpid *track_ecmpid, const NMPObject **out_obj_del)
{
    EcmpTrackObj                   *track_obj;
    nm_auto_nmpobj const NMPObject *obj_new = NULL;
    gsize                           n_nexthops;
    gsize                           i;

    nm_assert(track_ecmpid);
    nm_assert(!c_list_is_empty(&track_ecmpid->ecmpid_lst_head));
    nm_assert(track_ecmpid->representative_obj
              == c_list_first_entry(&track_ecmpid->ecmpid_lst_head, EcmpTrackObj, ecmpid_lst)->obj);
    nm_assert(out_obj_del && !*out_obj_del);

    if (!track_ecmpid->needs_update) {
        /* Already up to date. Nothing to do. */
        return FALSE;
    }

    track_ecmpid->needs_update = FALSE;

    n_nexthops = c_list_length(&track_ecmpid->ecmpid_lst_head);

    if (n_nexthops == 1) {
        /* There is only a single entry. There is nothing to merge, just set
         * the first entry. */
        obj_new = nmp_object_ref(track_ecmpid->representative_obj);
        goto out;
    }

    /* We want that the nexthop list is deterministic. We thus sort the list and update
     * the representative_obj. */
    c_list_sort(&track_ecmpid->ecmpid_lst_head, _ecmp_track_sort_lst_cmp, NULL);
    nmp_object_ref_set(
        &track_ecmpid->representative_obj,
        c_list_first_entry(&track_ecmpid->ecmpid_lst_head, EcmpTrackObj, ecmpid_lst)->obj);

    obj_new = nmp_object_clone(track_ecmpid->representative_obj, FALSE);

    nm_assert(obj_new->ip4_route.n_nexthops <= 1);
    nm_assert(!obj_new->_ip4_route.extra_nexthops);

    /* Note that there actually cannot be duplicate (ifindex,gateway,weight) tuples, because
     * NML3Cfg uses NM_PLATFORM_IP_ROUTE_CMP_TYPE_ID to track the routes, and track_ecmpid
     * groups them further by NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID. The comparison for
     * ECMP_ID is a strict superset of ID, hence there are no dupliated.
     *
     * Also, kernel wouldn't care if there were duplicate nexthops anyway.
     *
     * This means, it's gonna be simple. We sorted the single-hop routes by next-hop,
     * now just create a plain list of the nexthops (no check for duplciates, etc). */

    ((NMPObject *) obj_new)->ip4_route.n_nexthops = n_nexthops;
    ((NMPObject *) obj_new)->_ip4_route.extra_nexthops =
        g_new(NMPlatformIP4RtNextHop, n_nexthops - 1u);

    i = 0;
    c_list_for_each_entry (track_obj, &track_ecmpid->ecmpid_lst_head, ecmpid_lst) {
        if (i > 0) {
            const NMPlatformIP4Route *r  = NMP_OBJECT_CAST_IP4_ROUTE(track_obj->obj);
            NMPlatformIP4RtNextHop   *nh = (gpointer) &obj_new->_ip4_route.extra_nexthops[i - 1];

            *nh = (NMPlatformIP4RtNextHop){
                .ifindex = r->ifindex,
                .gateway = r->gateway,
                .weight  = r->weight,
            };
        }
        i++;
    }

out:
    nm_assert(obj_new);
    if (nmp_object_equal(track_ecmpid->merged_obj, obj_new))
        /* the objects are equal but the update was needed, for example if the
         * routes were removed from kernel but not from our tracking
         * dictionaries and therefore we tried to register them again. */
        return TRUE;

    if (track_ecmpid->merged_obj)
        *out_obj_del = g_steal_pointer(&track_ecmpid->merged_obj);
    track_ecmpid->merged_obj = g_steal_pointer(&obj_new);
    return TRUE;
}

/*****************************************************************************/

NMPNetns *
nm_netns_get_platform_netns(NMNetns *self)
{
    return NM_NETNS_GET_PRIVATE(self)->platform_netns;
}

NMPlatform *
nm_netns_get_platform(NMNetns *self)
{
    return NM_NETNS_GET_PRIVATE(self)->platform;
}

NMPGlobalTracker *
nm_netns_get_global_tracker(NMNetns *self)
{
    return NM_NETNS_GET_PRIVATE(self)->global_tracker;
}

NMDedupMultiIndex *
nm_netns_get_multi_idx(NMNetns *self)
{
    return nm_platform_get_multi_idx(NM_NETNS_GET_PRIVATE(self)->platform);
}

/*****************************************************************************/

static guint
_ecmp_routes_by_ecmpid_hash(gconstpointer ptr)
{
    const NMPObject *const *p_obj = ptr;

    return nm_platform_ip4_route_hash(NMP_OBJECT_CAST_IP4_ROUTE(*p_obj),
                                      NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID);
}

static int
_ecmp_routes_by_ecmpid_equal(gconstpointer ptr_a, gconstpointer ptr_b)
{
    const NMPObject *const *p_obj_a = ptr_a;
    const NMPObject *const *p_obj_b = ptr_b;

    return nm_platform_ip4_route_cmp(NMP_OBJECT_CAST_IP4_ROUTE(*p_obj_a),
                                     NMP_OBJECT_CAST_IP4_ROUTE(*p_obj_b),
                                     NM_PLATFORM_IP_ROUTE_CMP_TYPE_ECMP_ID)
           == 0;
}

static void
_ecmp_routes_by_ecmpid_free(gpointer ptr)
{
    EcmpTrackEcmpid *track_ecmpid = ptr;

    c_list_unlink_stale(&track_ecmpid->ecmpid_lst_head);
    nmp_object_unref(track_ecmpid->representative_obj);
    nmp_object_unref(track_ecmpid->merged_obj);
    nm_g_slice_free(track_ecmpid);
}

static void
_ecmp_routes_by_obj_free(gpointer ptr)
{
    EcmpTrackObj *track_obj = ptr;

    c_list_unlink_stale(&track_obj->ifindex_lst);
    c_list_unlink_stale(&track_obj->ecmpid_lst);
    nmp_object_unref(track_obj->obj);
    nm_g_slice_free(track_obj);
}

/*****************************************************************************/

static NML3Cfg *
_l3cfg_hashed_to_l3cfg(gpointer ptr)
{
    gpointer l3cfg;

    l3cfg = &(((char *) ptr)[-G_STRUCT_OFFSET(NML3Cfg, priv.ifindex)]);
    nm_assert(NM_IS_L3CFG(l3cfg));
    return l3cfg;
}

static void
_l3cfg_hashed_free(gpointer ptr)
{
    NML3Cfg *l3cfg = _l3cfg_hashed_to_l3cfg(ptr);

    c_list_unlink(&l3cfg->internal_netns.signal_pending_lst);
}

static void
_l3cfg_weak_notify(gpointer data, GObject *where_the_object_was)
{
    NMNetns        *self    = NM_NETNS(data);
    NMNetnsPrivate *priv    = NM_NETNS_GET_PRIVATE(data);
    NML3Cfg        *l3cfg   = NM_L3CFG(where_the_object_was);
    int             ifindex = nm_l3cfg_get_ifindex(l3cfg);

    if (!g_hash_table_remove(priv->l3cfgs, &ifindex))
        nm_assert_not_reached();

    if (NM_UNLIKELY(g_hash_table_size(priv->l3cfgs) == 0))
        g_object_unref(self);
}

NML3Cfg *
nm_netns_l3cfg_get(NMNetns *self, int ifindex)
{
    NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE(self);
    gpointer        ptr;

    nm_assert(ifindex > 0);

    ptr = g_hash_table_lookup(priv->l3cfgs, &ifindex);
    return ptr ? _l3cfg_hashed_to_l3cfg(ptr) : NULL;
}

NML3Cfg *
nm_netns_l3cfg_acquire(NMNetns *self, int ifindex)
{
    NMNetnsPrivate *priv;
    NML3Cfg        *l3cfg;

    g_return_val_if_fail(NM_IS_NETNS(self), NULL);
    g_return_val_if_fail(ifindex > 0, NULL);

    priv = NM_NETNS_GET_PRIVATE(self);

    l3cfg = nm_netns_l3cfg_get(self, ifindex);
    if (l3cfg) {
        nm_log_trace(LOGD_CORE,
                     "l3cfg[" NM_HASH_OBFUSCATE_PTR_FMT ",ifindex=%d] %s",
                     NM_HASH_OBFUSCATE_PTR(l3cfg),
                     ifindex,
                     "referenced");
        return g_object_ref(l3cfg);
    }

    l3cfg = nm_l3cfg_new(self, ifindex);

    if (!g_hash_table_add(priv->l3cfgs, &l3cfg->priv.ifindex))
        nm_assert_not_reached();

    if (NM_UNLIKELY(g_hash_table_size(priv->l3cfgs) == 1))
        g_object_ref(self);

    g_object_weak_ref(G_OBJECT(l3cfg), _l3cfg_weak_notify, self);

    /* Transfer ownership! We keep only a weak ref. */
    return l3cfg;
}

/*****************************************************************************/

static gboolean
_platform_signal_on_idle_cb(gpointer user_data)
{
    gs_unref_object NMNetns *self = g_object_ref(NM_NETNS(user_data));
    NMNetnsPrivate          *priv = NM_NETNS_GET_PRIVATE(self);
    NML3Cfg                 *l3cfg;
    CList                    work_list;

    nm_clear_g_source_inst(&priv->signal_pending_idle_source);

    /* we emit all queued signals together. However, we don't want to hook the
     * main loop for longer than the currently queued elements.
     *
     * If we catch more change events, they will be queued and processed by a future
     * idle handler.
     *
     * Hence, move the list to a temporary list. Isn't CList great? */

    c_list_init(&work_list);
    c_list_splice(&work_list, &priv->l3cfg_signal_pending_lst_head);

    while ((l3cfg = c_list_first_entry(&work_list, NML3Cfg, internal_netns.signal_pending_lst))) {
        nm_assert(NM_IS_L3CFG(l3cfg));
        c_list_unlink(&l3cfg->internal_netns.signal_pending_lst);
        _nm_l3cfg_notify_platform_change_on_idle(
            l3cfg,
            nm_steal_int(&l3cfg->internal_netns.signal_pending_obj_type_flags));
    }

    return G_SOURCE_CONTINUE;
}

static void
_platform_signal_cb(NMPlatform   *platform,
                    int           obj_type_i,
                    int           ifindex,
                    gconstpointer platform_object,
                    int           change_type_i,
                    NMNetns     **p_self)
{
    NMNetns                         *self        = NM_NETNS(*p_self);
    NMNetnsPrivate                  *priv        = NM_NETNS_GET_PRIVATE(self);
    const NMPObjectType              obj_type    = obj_type_i;
    const NMPlatformSignalChangeType change_type = change_type_i;
    NML3Cfg                         *l3cfg;

    if (ifindex <= 0) {
        /* platform signal callback could be triggered by nodev routes, skip them */
        return;
    }

    l3cfg = nm_netns_l3cfg_get(self, ifindex);
    if (!l3cfg)
        return;

    l3cfg->internal_netns.signal_pending_obj_type_flags |= nmp_object_type_to_flags(obj_type);

    if (c_list_is_empty(&l3cfg->internal_netns.signal_pending_lst)) {
        c_list_link_tail(&priv->l3cfg_signal_pending_lst_head,
                         &l3cfg->internal_netns.signal_pending_lst);
        if (!priv->signal_pending_idle_source)
            priv->signal_pending_idle_source =
                nm_g_idle_add_source(_platform_signal_on_idle_cb, self);
    }

    _nm_l3cfg_notify_platform_change(l3cfg, change_type, NMP_OBJECT_UP_CAST(platform_object));
}

/*****************************************************************************/

NMNetnsSharedIPHandle *
nm_netns_shared_ip_reserve(NMNetns *self)
{
    NMNetnsPrivate        *priv;
    NMNetnsSharedIPHandle *handle;
    const in_addr_t        addr_start = ntohl(0x0a2a0001u); /* 10.42.0.1 */
    in_addr_t              addr;
    char                   sbuf_addr[NM_INET_ADDRSTRLEN];

    /* Find an unused address in the 10.42.x.x range */

    g_return_val_if_fail(NM_IS_NETNS(self), NULL);

    priv = NM_NETNS_GET_PRIVATE(self);

    if (!priv->shared_ips) {
        addr             = addr_start;
        priv->shared_ips = g_hash_table_new(nm_puint32_hash, nm_puint32_equal);
        g_object_ref(self);
    } else {
        guint32 count;

        nm_assert(g_hash_table_size(priv->shared_ips) > 0);

        count = 0u;
        for (;;) {
            addr = addr_start + htonl(count << 8u);

            handle = g_hash_table_lookup(priv->shared_ips, &addr);
            if (!handle)
                break;

            count++;

            if (count > 0xFFu) {
                if (handle->_ref_count == 1) {
                    _LOGE("shared-ip4: ran out of shared IP addresses. Reuse %s/24",
                          nm_inet4_ntop(handle->addr, sbuf_addr));
                } else {
                    _LOGD("shared-ip4: reserved IP address range %s/24 (duplicate)",
                          nm_inet4_ntop(handle->addr, sbuf_addr));
                }
                handle->_ref_count++;
                return handle;
            }
        }
    }

    handle  = g_slice_new(NMNetnsSharedIPHandle);
    *handle = (NMNetnsSharedIPHandle){
        .addr       = addr,
        ._ref_count = 1,
        ._self      = self,
    };

    g_hash_table_add(priv->shared_ips, handle);

    _LOGD("shared-ip4: reserved IP address range %s/24", nm_inet4_ntop(handle->addr, sbuf_addr));
    return handle;
}

void
nm_netns_shared_ip_release(NMNetnsSharedIPHandle *handle)
{
    NMNetns        *self;
    NMNetnsPrivate *priv;
    char            sbuf_addr[NM_INET_ADDRSTRLEN];

    g_return_if_fail(handle);

    self = handle->_self;

    g_return_if_fail(NM_IS_NETNS(self));

    priv = NM_NETNS_GET_PRIVATE(self);

    nm_assert(handle->_ref_count > 0);
    nm_assert(handle == nm_g_hash_table_lookup(priv->shared_ips, handle));

    if (handle->_ref_count > 1) {
        nm_assert(handle->addr == ntohl(0x0A2AFF01u)); /* 10.42.255.1 */
        handle->_ref_count--;
        _LOGD("shared-ip4: release IP address range %s/24 (%d more references held)",
              nm_inet4_ntop(handle->addr, sbuf_addr),
              handle->_ref_count);
        return;
    }

    if (!g_hash_table_remove(priv->shared_ips, handle))
        nm_assert_not_reached();

    if (g_hash_table_size(priv->shared_ips) == 0) {
        nm_clear_pointer(&priv->shared_ips, g_hash_table_unref);
        g_object_unref(self);
    }

    _LOGD("shared-ip4: release IP address range %s/24", nm_inet4_ntop(handle->addr, sbuf_addr));

    handle->_self = NULL;
    nm_g_slice_free(handle);
}

/*****************************************************************************/

void
nm_netns_ip_route_ecmp_register(NMNetns *self, NML3Cfg *l3cfg, const NMPObject *obj)
{
    NMNetnsPrivate           *priv;
    EcmpTrackObj             *track_obj;
    const NMPlatformIP4Route *route;
    char                      sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];

    nm_assert_l3cfg(self, l3cfg);

    route = NMP_OBJECT_CAST_IP4_ROUTE(obj);

    nm_assert(route->ifindex > 0);
    nm_assert(route->ifindex == nm_l3cfg_get_ifindex(l3cfg));
    nm_assert(route->n_nexthops <= 1);

    priv = NM_NETNS_GET_PRIVATE(self);

    track_obj = g_hash_table_lookup(priv->ecmp_track_by_obj, &obj);

    if (NM_MORE_ASSERTS > 10) {
        EcmpTrackObj *track_obj2;
        gboolean      found = FALSE;

        c_list_for_each_entry (track_obj2,
                               &l3cfg->internal_netns.ecmp_track_ifindex_lst_head,
                               ifindex_lst) {
            if (track_obj2->obj == obj) {
                found = TRUE;
                break;
            }
        }

        nm_assert((!!track_obj) == found);
    }

    if (!track_obj) {
        EcmpTrackEcmpid *track_ecmpid;

        track_ecmpid = g_hash_table_lookup(priv->ecmp_track_by_ecmpid, &obj);
        if (!track_ecmpid) {
            track_ecmpid  = g_slice_new(EcmpTrackEcmpid);
            *track_ecmpid = (EcmpTrackEcmpid){
                .representative_obj = nmp_object_ref(obj),
                .merged_obj         = NULL,
                .ecmpid_lst_head    = C_LIST_INIT(track_ecmpid->ecmpid_lst_head),
                .needs_update       = TRUE,
            };
            g_hash_table_add(priv->ecmp_track_by_ecmpid, track_ecmpid);
        } else
            track_ecmpid->needs_update = TRUE;

        track_obj  = g_slice_new(EcmpTrackObj);
        *track_obj = (EcmpTrackObj){
            .obj                 = nmp_object_ref(obj),
            .l3cfg               = l3cfg,
            .parent_track_ecmpid = track_ecmpid,
            .dirty               = FALSE,
            .is_new              = TRUE,
            .is_ready            = FALSE,
        };

        g_hash_table_add(priv->ecmp_track_by_obj, track_obj);
        c_list_link_tail(&l3cfg->internal_netns.ecmp_track_ifindex_lst_head,
                         &track_obj->ifindex_lst);
        c_list_link_tail(&track_ecmpid->ecmpid_lst_head, &track_obj->ecmpid_lst);

        _LOGT(
            "ecmp-route: track %s",
            nmp_object_to_string(track_obj->obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
    } else {
        track_obj->dirty                             = FALSE;
        track_obj->parent_track_ecmpid->needs_update = TRUE;
    }
}

void
nm_netns_ip_route_ecmp_commit(NMNetns    *self,
                              NML3Cfg    *l3cfg,
                              GPtrArray **out_singlehop_routes,
                              gboolean    is_reapply)
{
    NMNetnsPrivate  *priv = NM_NETNS_GET_PRIVATE(self);
    EcmpTrackObj    *track_obj;
    EcmpTrackObj    *track_obj_safe;
    EcmpTrackEcmpid *track_ecmpid;
    const NMPObject *route_obj;
    char             sbuf[NM_UTILS_TO_STRING_BUFFER_SIZE];
    gboolean         already_notified = FALSE;

    nm_assert_l3cfg(self, l3cfg);

    _LOGT("ecmp-route: committing IPv4 ECMP routes");

    /* First, delete all dirty entries, and mark the survivors as dirty, so that on the
     * next update they must be touched again. */
    c_list_for_each_entry_safe (track_obj,
                                track_obj_safe,
                                &l3cfg->internal_netns.ecmp_track_ifindex_lst_head,
                                ifindex_lst) {
        track_ecmpid                  = track_obj->parent_track_ecmpid;
        track_ecmpid->already_visited = FALSE;

        nm_assert(g_hash_table_lookup(priv->ecmp_track_by_ecmpid, track_ecmpid) == track_ecmpid);
        nm_assert(g_hash_table_lookup(priv->ecmp_track_by_obj, track_obj) == track_obj);
        nm_assert(c_list_contains(&track_ecmpid->ecmpid_lst_head, &track_obj->ecmpid_lst));
        nm_assert(track_obj->l3cfg == l3cfg);

        if (!track_obj->dirty) {
            /* This one is still in used. Keep it, but mark dirty, so that on the
             * next update cycle, it needs to be touched again or will be deleted. */
            track_obj->dirty = TRUE;
            if (is_reapply) {
                track_obj->is_new   = TRUE;
                track_obj->is_ready = FALSE;
            }
            if (track_obj->is_new) {
                const NMPlatformIP4Route *route =
                    NMP_OBJECT_CAST_IP4_ROUTE(track_ecmpid->merged_obj);

                /* This is a new route entry that was just added. Upon first
                 * addition, the route is not yet ready for configuration,
                 * because we need to make sure that the gateway is reachable
                 * via an onlink route. The calling l3cfg will configure that
                 * route, but only after returning from this function.  So we
                 * need to go through one more commit.
                 *
                 * We also need to make sure that we are called back right
                 * after l3cfg configured that route. We achieve that by
                 * scheduling another idle commit on "l3cfg". */
                track_obj->is_new = FALSE;
                if (route
                    && (route->gateway == 0
                        || NM_FLAGS_HAS(route->r_rtm_flags, (unsigned) RTNH_F_ONLINK))) {
                    /* This route is onlink. We don't need to configure an onlink route
                     * to the gateway, and the route is immediately ready for configuration. */
                    track_obj->is_ready = TRUE;
                } else if (c_list_length_is(&track_ecmpid->ecmpid_lst_head, 1)) {
                    /* This route has no merge partner and ends up being a
                     * single hop route. It will be returned and configured by
                     * the calling "l3cfg".
                     *
                     * Unlike for multi-hop routes, we don't need to be called
                     * again after the onlink route was added. We are done, and
                     * don't need to schedule an idle commit. */
                    track_obj->is_ready = TRUE;
                } else {
                    /* This is a new route which has a gateway. We need for the "l3cfg"
                     * to first configure the onlink route. It's not yet ready for configuration.
                     *
                     * Instead, schedule an idle commit to make sure we get called back
                     * again, and then (upon seeing the entry the second time) the onlink
                     * route is already configured and we will be ready. */
                    if (!already_notified) {
                        /* Some micro optimization with already_notified to avoid calling
                         * schedule unnecessarily. */
                        already_notified = TRUE;
                        nm_l3cfg_commit_on_idle_schedule(l3cfg, NM_L3_CFG_COMMIT_TYPE_AUTO);
                    }
                }
            } else {
                /* We see this entry the second time (or more) so it's ready. */
                track_obj->is_ready = TRUE;
            }
            continue;
        }

        /* This entry can be dropped. */
        if (!g_hash_table_remove(priv->ecmp_track_by_obj, track_obj))
            nm_assert_not_reached();

        if (c_list_is_empty(&track_ecmpid->ecmpid_lst_head)) {
            if (track_ecmpid->merged_obj) {
                if (NMP_OBJECT_CAST_IP4_ROUTE(track_ecmpid->merged_obj)->n_nexthops > 1)
                    nm_platform_object_delete(priv->platform, track_ecmpid->merged_obj);
            }
            g_hash_table_remove(priv->ecmp_track_by_ecmpid, track_ecmpid);

            continue;
        }

        /* We need to update the representative obj. */
        nmp_object_ref_set(
            &track_ecmpid->representative_obj,
            c_list_first_entry(&track_ecmpid->ecmpid_lst_head, EcmpTrackObj, ecmpid_lst)->obj);
        track_ecmpid->needs_update = TRUE;
    }

    /* Now, we need to iterate again over all objects, and regenerate the merged_obj. */
    c_list_for_each_entry (track_obj,
                           &l3cfg->internal_netns.ecmp_track_ifindex_lst_head,
                           ifindex_lst) {
        const NMPlatformIP4Route       *route;
        EcmpTrackObj                   *track_obj2;
        nm_auto_nmpobj const NMPObject *obj_del = NULL;
        gboolean                        changed;
        gboolean                        all_is_ready;

        track_ecmpid = track_obj->parent_track_ecmpid;
        if (track_ecmpid->already_visited) {
            /* We already visited this ecmpid in the same loop. We can skip, otherwise
             * we might add the same route twice. */
            continue;
        }
        track_ecmpid->already_visited = TRUE;

        all_is_ready = TRUE;
        c_list_for_each_entry (track_obj2, &track_ecmpid->ecmpid_lst_head, ecmpid_lst) {
            if (!track_obj2->is_ready) {
                all_is_ready = FALSE;
                break;
            }
        }
        if (!all_is_ready) {
            /* Here we might have a merged_obj already which can have the wrong
             * setting e.g the wrong nexthops. We leave them for the moment and
             * then we reconfigure it when this entry is ready. */
            continue;
        }

        changed = _ecmp_track_init_merged_obj(track_obj->parent_track_ecmpid, &obj_del);

        nm_assert(!obj_del || changed);

        route_obj = track_ecmpid->merged_obj;
        route     = NMP_OBJECT_CAST_IP4_ROUTE(route_obj);

        if (obj_del) {
            if (NMP_OBJECT_CAST_IP4_ROUTE(obj_del)->n_nexthops > 1)
                nm_platform_object_delete(priv->platform, obj_del);
            else if (track_obj->l3cfg != l3cfg)
                nm_l3cfg_commit_on_idle_schedule(track_obj->l3cfg, NM_L3_CFG_COMMIT_TYPE_AUTO);
        }

        if (route->n_nexthops <= 1) {
            /* This is a single hop route. Return it to the caller. */
            if (!*out_singlehop_routes) {
                /* Note that the returned array does not own a reference. This
                 * function has only one caller, and for that caller, it's just
                 * fine that the result is not additionally kept alive. */
                *out_singlehop_routes =
                    g_ptr_array_new_with_free_func((GDestroyNotify) nmp_object_unref);
            }
            g_ptr_array_add(*out_singlehop_routes, (gpointer) nmp_object_ref(route_obj));
            if (changed) {
                _LOGT("ecmp-route: single-hop %s",
                      nmp_object_to_string(route_obj,
                                           NMP_OBJECT_TO_STRING_PUBLIC,
                                           sbuf,
                                           sizeof(sbuf)));
            }
            continue;
        }

        if (changed || is_reapply) {
            _LOGT("ecmp-route: multi-hop %s",
                  nmp_object_to_string(route_obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof(sbuf)));
            nm_platform_ip_route_add(priv->platform, NMP_NLM_FLAG_APPEND, route_obj);
        }
    }
}

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMNetns        *self = NM_NETNS(object);
    NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE(self);

    switch (prop_id) {
    case PROP_PLATFORM:
        /* construct-only */
        priv->platform = g_value_get_object(value) ?: NM_PLATFORM_GET;
        if (!priv->platform)
            g_return_if_reached();
        g_object_ref(priv->platform);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*****************************************************************************/

static void
nm_netns_init(NMNetns *self)
{
    NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE(self);

    priv->_self_signal_user_data = self;
    c_list_init(&priv->l3cfg_signal_pending_lst_head);

    G_STATIC_ASSERT_EXPR(G_STRUCT_OFFSET(EcmpTrackObj, obj) == 0);
    priv->ecmp_track_by_obj =
        g_hash_table_new_full(nm_pdirect_hash, nm_pdirect_equal, _ecmp_routes_by_obj_free, NULL);
    priv->ecmp_track_by_ecmpid = g_hash_table_new_full(_ecmp_routes_by_ecmpid_hash,
                                                       _ecmp_routes_by_ecmpid_equal,
                                                       _ecmp_routes_by_ecmpid_free,
                                                       NULL);
}

static void
constructed(GObject *object)
{
    NMNetns        *self = NM_NETNS(object);
    NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE(self);

    if (!priv->platform)
        g_return_if_reached();

    priv->l3cfgs = g_hash_table_new_full(nm_pint_hash, nm_pint_equal, _l3cfg_hashed_free, NULL);

    priv->platform_netns = nm_platform_netns_get(priv->platform);

    priv->global_tracker = nmp_global_tracker_new(priv->platform);

    /* Weakly track the default rules with a dummy user-tag. These
     * rules are always weekly tracked... */
    nmp_global_tracker_track_rule_default(priv->global_tracker,
                                          AF_UNSPEC,
                                          0,
                                          nm_netns_parent_class /* static dummy user-tag */);

    /* Also weakly track all existing rules. These were added before NetworkManager
     * starts, so they are probably none of NetworkManager's business.
     *
     * However note that during service restart, devices may stay up and rules kept.
     * That means, after restart such rules may have been added by a previous run
     * of NetworkManager, we just don't know.
     *
     * For that reason, whenever we will touch such rules later one, we make them
     * fully owned and no longer weekly tracked. See %NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG. */
    nmp_global_tracker_track_rule_from_platform(priv->global_tracker,
                                                NULL,
                                                AF_UNSPEC,
                                                0,
                                                NMP_GLOBAL_TRACKER_EXTERN_WEAKLY_TRACKED_USER_TAG);

    G_OBJECT_CLASS(nm_netns_parent_class)->constructed(object);

    g_signal_connect(priv->platform,
                     NM_PLATFORM_SIGNAL_LINK_CHANGED,
                     G_CALLBACK(_platform_signal_cb),
                     &priv->_self_signal_user_data);
    g_signal_connect(priv->platform,
                     NM_PLATFORM_SIGNAL_IP4_ROUTE_CHANGED,
                     G_CALLBACK(_platform_signal_cb),
                     &priv->_self_signal_user_data);
    g_signal_connect(priv->platform,
                     NM_PLATFORM_SIGNAL_IP6_ROUTE_CHANGED,
                     G_CALLBACK(_platform_signal_cb),
                     &priv->_self_signal_user_data);
    g_signal_connect(priv->platform,
                     NM_PLATFORM_SIGNAL_IP4_ADDRESS_CHANGED,
                     G_CALLBACK(_platform_signal_cb),
                     &priv->_self_signal_user_data);
    g_signal_connect(priv->platform,
                     NM_PLATFORM_SIGNAL_IP6_ADDRESS_CHANGED,
                     G_CALLBACK(_platform_signal_cb),
                     &priv->_self_signal_user_data);
}

NMNetns *
nm_netns_new(NMPlatform *platform)
{
    return g_object_new(NM_TYPE_NETNS, NM_NETNS_PLATFORM, platform, NULL);
}

static void
dispose(GObject *object)
{
    NMNetns        *self = NM_NETNS(object);
    NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE(self);

    nm_assert(nm_g_hash_table_size(priv->l3cfgs) == 0);
    nm_assert(c_list_is_empty(&priv->l3cfg_signal_pending_lst_head));
    nm_assert(!priv->shared_ips);

    nm_clear_pointer(&priv->ecmp_track_by_obj, g_hash_table_destroy);
    nm_clear_pointer(&priv->ecmp_track_by_ecmpid, g_hash_table_destroy);

    nm_clear_g_source_inst(&priv->signal_pending_idle_source);

    if (priv->platform)
        g_signal_handlers_disconnect_by_data(priv->platform, &priv->_self_signal_user_data);

    g_clear_object(&priv->platform);
    nm_clear_pointer(&priv->l3cfgs, g_hash_table_unref);

    nm_clear_pointer(&priv->global_tracker, nmp_global_tracker_unref);

    G_OBJECT_CLASS(nm_netns_parent_class)->dispose(object);
}

static void
nm_netns_class_init(NMNetnsClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->constructed  = constructed;
    object_class->set_property = set_property;
    object_class->dispose      = dispose;

    obj_properties[PROP_PLATFORM] =
        g_param_spec_object(NM_NETNS_PLATFORM,
                            "",
                            "",
                            NM_TYPE_PLATFORM,
                            G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
