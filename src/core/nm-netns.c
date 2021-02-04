/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-netns.h"

#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-glib-aux/nm-c-list.h"

#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-l3cfg.h"
#include "platform/nm-platform.h"
#include "nm-platform/nmp-netns.h"
#include "platform/nmp-rules-manager.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE(PROP_PLATFORM, );

typedef struct {
    NMNetns *        _self_signal_user_data;
    NMPlatform *     platform;
    NMPNetns *       platform_netns;
    NMPRulesManager *rules_manager;
    GHashTable *     l3cfgs;
    GHashTable *     shared_ips;
    CList            l3cfg_signal_pending_lst_head;
    guint            signal_pending_idle_id;
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

NMPRulesManager *
nm_netns_get_rules_manager(NMNetns *self)
{
    return NM_NETNS_GET_PRIVATE(self)->rules_manager;
}

NMDedupMultiIndex *
nm_netns_get_multi_idx(NMNetns *self)
{
    return nm_platform_get_multi_idx(NM_NETNS_GET_PRIVATE(self)->platform);
}

/*****************************************************************************/

typedef struct {
    int      ifindex;
    guint32  signal_pending_obj_type_flags;
    NML3Cfg *l3cfg;
    CList    signal_pending_lst;
} L3CfgData;

static void
_l3cfg_data_free(gpointer ptr)
{
    L3CfgData *l3cfg_data = ptr;

    c_list_unlink_stale(&l3cfg_data->signal_pending_lst);

    nm_g_slice_free(l3cfg_data);
}

static void
_l3cfg_weak_notify(gpointer data, GObject *where_the_object_was)
{
    NMNetns *       self    = NM_NETNS(data);
    NMNetnsPrivate *priv    = NM_NETNS_GET_PRIVATE(data);
    NML3Cfg *       l3cfg   = NM_L3CFG(where_the_object_was);
    int             ifindex = nm_l3cfg_get_ifindex(l3cfg);

    if (!g_hash_table_remove(priv->l3cfgs, &ifindex))
        nm_assert_not_reached();

    if (NM_UNLIKELY(g_hash_table_size(priv->l3cfgs) == 0))
        g_object_unref(self);
}

NML3Cfg *
nm_netns_get_l3cfg(NMNetns *self, int ifindex)
{
    NMNetnsPrivate *priv;

    g_return_val_if_fail(NM_IS_NETNS(self), NULL);
    g_return_val_if_fail(ifindex > 0, NULL);

    priv = NM_NETNS_GET_PRIVATE(self);

    return g_hash_table_lookup(priv->l3cfgs, &ifindex);
}

NML3Cfg *
nm_netns_access_l3cfg(NMNetns *self, int ifindex)
{
    NMNetnsPrivate *priv;
    L3CfgData *     l3cfg_data;

    g_return_val_if_fail(NM_IS_NETNS(self), NULL);
    g_return_val_if_fail(ifindex > 0, NULL);

    priv = NM_NETNS_GET_PRIVATE(self);

    l3cfg_data = g_hash_table_lookup(priv->l3cfgs, &ifindex);

    if (l3cfg_data) {
        nm_log_trace(LOGD_CORE,
                     "l3cfg[" NM_HASH_OBFUSCATE_PTR_FMT ",ifindex=%d] %s",
                     NM_HASH_OBFUSCATE_PTR(l3cfg_data->l3cfg),
                     ifindex,
                     "referenced");
        return g_object_ref(l3cfg_data->l3cfg);
    }

    l3cfg_data  = g_slice_new(L3CfgData);
    *l3cfg_data = (L3CfgData){
        .ifindex            = ifindex,
        .l3cfg              = nm_l3cfg_new(self, ifindex),
        .signal_pending_lst = C_LIST_INIT(l3cfg_data->signal_pending_lst),
    };

    if (!g_hash_table_add(priv->l3cfgs, l3cfg_data))
        nm_assert_not_reached();

    if (NM_UNLIKELY(g_hash_table_size(priv->l3cfgs) == 1))
        g_object_ref(self);

    g_object_weak_ref(G_OBJECT(l3cfg_data->l3cfg), _l3cfg_weak_notify, self);

    /* Transfer ownership! We keep only a weak ref. */
    return l3cfg_data->l3cfg;
}

/*****************************************************************************/

static gboolean
_platform_signal_on_idle_cb(gpointer user_data)
{
    gs_unref_object NMNetns *self = g_object_ref(NM_NETNS(user_data));
    NMNetnsPrivate *         priv = NM_NETNS_GET_PRIVATE(self);
    L3CfgData *              l3cfg_data;
    CList                    work_list;

    priv->signal_pending_idle_id = 0;

    /* we emit all queued signals together. However, we don't want to hook the
     * main loop for longer than the currently queued elements.
     *
     * If we catch more change events, they will be queued and processed by a future
     * idle handler.
     *
     * Hence, move the list to a temporary list. Isn't CList great? */

    c_list_init(&work_list);
    c_list_splice(&work_list, &priv->l3cfg_signal_pending_lst_head);

    while ((l3cfg_data = c_list_first_entry(&work_list, L3CfgData, signal_pending_lst))) {
        nm_assert(NM_IS_L3CFG(l3cfg_data->l3cfg));
        c_list_unlink(&l3cfg_data->signal_pending_lst);
        _nm_l3cfg_notify_platform_change_on_idle(
            l3cfg_data->l3cfg,
            nm_steal_int(&l3cfg_data->signal_pending_obj_type_flags));
    }

    return G_SOURCE_REMOVE;
}

static void
_platform_signal_cb(NMPlatform *  platform,
                    int           obj_type_i,
                    int           ifindex,
                    gconstpointer platform_object,
                    int           change_type_i,
                    NMNetns **    p_self)
{
    NMNetns *                        self        = NM_NETNS(*p_self);
    NMNetnsPrivate *                 priv        = NM_NETNS_GET_PRIVATE(self);
    const NMPObjectType              obj_type    = obj_type_i;
    const NMPlatformSignalChangeType change_type = change_type_i;
    L3CfgData *                      l3cfg_data;

    l3cfg_data = g_hash_table_lookup(priv->l3cfgs, &ifindex);
    if (!l3cfg_data)
        return;

    l3cfg_data->signal_pending_obj_type_flags |= nmp_object_type_to_flags(obj_type);

    if (c_list_is_empty(&l3cfg_data->signal_pending_lst)) {
        c_list_link_tail(&priv->l3cfg_signal_pending_lst_head, &l3cfg_data->signal_pending_lst);
        if (priv->signal_pending_idle_id == 0)
            priv->signal_pending_idle_id = g_idle_add(_platform_signal_on_idle_cb, self);
    }

    _nm_l3cfg_notify_platform_change(l3cfg_data->l3cfg,
                                     change_type,
                                     NMP_OBJECT_UP_CAST(platform_object));
}

/*****************************************************************************/

NMNetnsSharedIPHandle *
nm_netns_shared_ip_reserve(NMNetns *self)
{
    NMNetnsPrivate *       priv;
    NMNetnsSharedIPHandle *handle;
    const in_addr_t        addr_start = ntohl(0x0a2a0001u); /* 10.42.0.1 */
    in_addr_t              addr;
    char                   sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];

    /* Find an unused address in the 10.42.x.x range */

    g_return_val_if_fail(NM_IS_NETNS(self), NULL);

    priv = NM_NETNS_GET_PRIVATE(self);

    if (!priv->shared_ips) {
        addr             = addr_start;
        priv->shared_ips = g_hash_table_new(nm_puint32_hash, nm_puint32_equals);
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
                          _nm_utils_inet4_ntop(handle->addr, sbuf_addr));
                } else {
                    _LOGD("shared-ip4: reserved IP address range %s/24 (duplicate)",
                          _nm_utils_inet4_ntop(handle->addr, sbuf_addr));
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

    _LOGD("shared-ip4: reserved IP address range %s/24",
          _nm_utils_inet4_ntop(handle->addr, sbuf_addr));
    return handle;
}

void
nm_netns_shared_ip_release(NMNetnsSharedIPHandle *handle)
{
    NMNetns *       self;
    NMNetnsPrivate *priv;
    char            sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];

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
              _nm_utils_inet4_ntop(handle->addr, sbuf_addr),
              handle->_ref_count);
        return;
    }

    if (!g_hash_table_remove(priv->shared_ips, handle))
        nm_assert_not_reached();

    if (g_hash_table_size(priv->shared_ips) == 0) {
        nm_clear_pointer(&priv->shared_ips, g_hash_table_unref);
        g_object_unref(self);
    }

    _LOGD("shared-ip4: release IP address range %s/24",
          _nm_utils_inet4_ntop(handle->addr, sbuf_addr));

    handle->_self = NULL;
    nm_g_slice_free(handle);
}

/*****************************************************************************/

static void
set_property(GObject *object, guint prop_id, const GValue *value, GParamSpec *pspec)
{
    NMNetns *       self = NM_NETNS(object);
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
}

static void
constructed(GObject *object)
{
    NMNetns *       self = NM_NETNS(object);
    NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE(self);

    if (!priv->platform)
        g_return_if_reached();

    priv->l3cfgs = g_hash_table_new_full(nm_pint_hash, nm_pint_equals, _l3cfg_data_free, NULL);

    priv->platform_netns = nm_platform_netns_get(priv->platform);

    priv->rules_manager = nmp_rules_manager_new(priv->platform);

    /* Weakly track the default rules with a dummy user-tag. These
     * rules are always weekly tracked... */
    nmp_rules_manager_track_default(priv->rules_manager,
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
     * fully owned and no longer weekly tracked. See %NMP_RULES_MANAGER_EXTERN_WEAKLY_TRACKED_USER_TAG. */
    nmp_rules_manager_track_from_platform(priv->rules_manager,
                                          NULL,
                                          AF_UNSPEC,
                                          0,
                                          NMP_RULES_MANAGER_EXTERN_WEAKLY_TRACKED_USER_TAG);

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
    NMNetns *       self = NM_NETNS(object);
    NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE(self);

    nm_assert(nm_g_hash_table_size(priv->l3cfgs) == 0);
    nm_assert(c_list_is_empty(&priv->l3cfg_signal_pending_lst_head));
    nm_assert(!priv->shared_ips);

    nm_clear_g_source(&priv->signal_pending_idle_id);

    if (priv->platform)
        g_signal_handlers_disconnect_by_data(priv->platform, &priv->_self_signal_user_data);

    g_clear_object(&priv->platform);
    nm_clear_pointer(&priv->l3cfgs, g_hash_table_unref);

    nm_clear_pointer(&priv->rules_manager, nmp_rules_manager_unref);

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
