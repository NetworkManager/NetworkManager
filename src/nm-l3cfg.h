/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_L3CFG_H__
#define __NM_L3CFG_H__

#include "platform/nmp-object.h"
#include "nm-l3-config-data.h"

#define NM_L3CFG_CONFIG_PRIORITY_IPV4LL 0
#define NM_ACD_TIMEOUT_RFC5227_MSEC     9000u

#define NM_TYPE_L3CFG            (nm_l3cfg_get_type())
#define NM_L3CFG(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_L3CFG, NML3Cfg))
#define NM_L3CFG_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_L3CFG, NML3CfgClass))
#define NM_IS_L3CFG(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_L3CFG))
#define NM_IS_L3CFG_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_L3CFG))
#define NM_L3CFG_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_L3CFG, NML3CfgClass))

#define NM_L3CFG_NETNS   "netns"
#define NM_L3CFG_IFINDEX "ifindex"

#define NM_L3CFG_SIGNAL_NOTIFY "l3cfg-notify"

typedef enum _nm_packed {
    NM_L3_ACD_DEFEND_TYPE_NONE,
    NM_L3_ACD_DEFEND_TYPE_NEVER,
    NM_L3_ACD_DEFEND_TYPE_ONCE,
    NM_L3_ACD_DEFEND_TYPE_ALWAYS,
} NML3AcdDefendType;

typedef enum _nm_packed {
    NM_L3_ACD_ADDR_STATE_INIT,
    NM_L3_ACD_ADDR_STATE_PROBING,
    NM_L3_ACD_ADDR_STATE_USED,
    NM_L3_ACD_ADDR_STATE_READY,
    NM_L3_ACD_ADDR_STATE_DEFENDING,
    NM_L3_ACD_ADDR_STATE_CONFLICT,
    NM_L3_ACD_ADDR_STATE_EXTERNAL_REMOVED,
} NML3AcdAddrState;

typedef struct {
    const NMPObject *     obj;
    const NML3ConfigData *l3cd;
    gconstpointer         tag;

    struct {
        guint32           acd_timeout_msec_track;
        NML3AcdDefendType acd_defend_type_track;
        bool              acd_dirty_track : 1;
        bool              acd_failed_notified_track : 1;
    } _priv;

} NML3AcdAddrTrackInfo;

typedef struct {
    in_addr_t                   addr;
    guint                       n_track_infos;
    NML3AcdAddrState            state;
    NML3Cfg *                   l3cfg;
    const NML3AcdAddrTrackInfo *track_infos;
} NML3AcdAddrInfo;

static inline const NML3AcdAddrTrackInfo *
nm_l3_acd_addr_info_find_track_info(const NML3AcdAddrInfo *addr_info,
                                    gconstpointer          tag,
                                    const NML3ConfigData * l3cd,
                                    const NMPObject *      obj)
{
    guint                       i;
    const NML3AcdAddrTrackInfo *ti;

    nm_assert(addr_info);

    /* we always expect that the number n_track_infos is reasonably small. Hence,
     * a naive linear search is simplest and fastest (e.g. we don't have a hash table). */

    for (i = 0, ti = addr_info->track_infos; i < addr_info->n_track_infos; i++, ti++) {
        if (l3cd && ti->l3cd != l3cd)
            continue;
        if (tag && ti->tag != tag)
            continue;
        if (obj && ti->obj != obj)
            continue;
        return ti;
    }

    return NULL;
}

typedef enum {
    NM_L3_CONFIG_NOTIFY_TYPE_ROUTES_TEMPORARY_NOT_AVAILABLE_EXPIRED,

    NM_L3_CONFIG_NOTIFY_TYPE_ACD_EVENT,

    /* emitted at the end of nm_l3cfg_platform_commit(). */
    NM_L3_CONFIG_NOTIFY_TYPE_POST_COMMIT,

    /* NML3Cfg hooks to the NMPlatform signals for link, addresses and routes.
     * It re-emits the platform signal.
     * Contrary to NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE, this even
     * is re-emitted synchronously. */
    NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE,

    /* NML3Cfg hooks to the NMPlatform signals for link, addresses and routes.
     * It re-emits the signal on an idle handler. The purpose is for something
     * like NMDevice which is already subscribed to these signals, it can get the
     * notifications without also subscribing directly to the platform. */
    NM_L3_CONFIG_NOTIFY_TYPE_PLATFORM_CHANGE_ON_IDLE,

    NM_L3_CONFIG_NOTIFY_TYPE_IPV4LL_EVENT,

    _NM_L3_CONFIG_NOTIFY_TYPE_NUM,
} NML3ConfigNotifyType;

struct _NML3IPv4LL;

typedef struct {
    NML3ConfigNotifyType notify_type;
    union {
        struct {
            NML3AcdAddrInfo info;
        } acd_event;

        struct {
            const NMPObject *          obj;
            NMPlatformSignalChangeType change_type;
        } platform_change;

        struct {
            guint32 obj_type_flags;
        } platform_change_on_idle;

        struct {
            struct _NML3IPv4LL *ipv4ll;
        } ipv4ll_event;
    };
} NML3ConfigNotifyData;

struct _NML3CfgPrivate;

struct _NML3Cfg {
    GObject parent;
    struct {
        struct _NML3CfgPrivate *p;
        NMNetns *               netns;
        NMPlatform *            platform;
        const NMPObject *       plobj;
        const NMPObject *       plobj_next;
        int                     ifindex;
    } priv;
};

typedef struct _NML3CfgClass NML3CfgClass;

GType nm_l3cfg_get_type(void);

NML3Cfg *nm_l3cfg_new(NMNetns *netns, int ifindex);

/*****************************************************************************/

void _nm_l3cfg_notify_platform_change_on_idle(NML3Cfg *self, guint32 obj_type_flags);

void _nm_l3cfg_notify_platform_change(NML3Cfg *                  self,
                                      NMPlatformSignalChangeType change_type,
                                      const NMPObject *          obj);

/*****************************************************************************/

struct _NMDedupMultiIndex;

struct _NMDedupMultiIndex *nm_netns_get_multi_idx(NMNetns *self);

static inline struct _NMDedupMultiIndex *
nm_l3cfg_get_multi_idx(const NML3Cfg *self)
{
    return nm_netns_get_multi_idx(self->priv.netns);
}

/*****************************************************************************/

static inline int
nm_l3cfg_get_ifindex(const NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    return self->priv.ifindex;
}

static inline const NMPObject *
nm_l3cfg_get_plobj(const NML3Cfg *self, gboolean get_next)
{
    if (!self)
        return NULL;

    nm_assert(NM_IS_L3CFG(self));

    if (get_next) {
        /* This is the instance that we just got reported in the last signal from
         * the platform cache. It's probably exactly the same as if you would look
         * into the platform cache.
         *
         * On the other hand, we pick up changes only on an idle handler. So the last
         * decisions were not made based on this, but instead of "plobj". */
        return self->priv.plobj_next;
    }
    return self->priv.plobj;
}

static inline const NMPlatformLink *
nm_l3cfg_get_pllink(const NML3Cfg *self, gboolean get_next)
{
    return NMP_OBJECT_CAST_LINK(nm_l3cfg_get_plobj(self, get_next));
}

static inline const char *
nm_l3cfg_get_ifname(const NML3Cfg *self, gboolean get_next)
{
    return nmp_object_link_get_ifname(nm_l3cfg_get_plobj(self, get_next));
}

static inline NMNetns *
nm_l3cfg_get_netns(const NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    return self->priv.netns;
}

static inline NMPlatform *
nm_l3cfg_get_platform(const NML3Cfg *self)
{
    nm_assert(NM_IS_L3CFG(self));

    return self->priv.platform;
}

gboolean nm_l3cfg_get_acd_is_pending(NML3Cfg *self);

/*****************************************************************************/

void _nm_l3cfg_emit_signal_notify(NML3Cfg *self, const NML3ConfigNotifyData *notify_data);

/*****************************************************************************/

typedef enum {
    NM_L3CFG_PROPERTY_EMIT_TYPE_ANY,
    NM_L3CFG_PROPERTY_EMIT_TYPE_IP4_ROUTE,
    NM_L3CFG_PROPERTY_EMIT_TYPE_IP6_ROUTE,
} NML3CfgPropertyEmitType;

void nm_l3cfg_property_emit_register(NML3Cfg *               self,
                                     GObject *               target_obj,
                                     const GParamSpec *      target_property,
                                     NML3CfgPropertyEmitType emit_type);

void nm_l3cfg_property_emit_unregister(NML3Cfg *         self,
                                       GObject *         target_obj,
                                       const GParamSpec *target_property);

/*****************************************************************************/

void nm_l3cfg_mark_config_dirty(NML3Cfg *self, gconstpointer tag, gboolean dirty);

gboolean nm_l3cfg_add_config(NML3Cfg *             self,
                             gconstpointer         tag,
                             gboolean              replace_same_tag,
                             const NML3ConfigData *l3cd,
                             int                   priority,
                             guint32               default_route_table_4,
                             guint32               default_route_table_6,
                             guint32               default_route_metric_4,
                             guint32               default_route_metric_6,
                             guint32               default_route_penalty_4,
                             guint32               default_route_penalty_6,
                             NML3AcdDefendType     acd_defend_type,
                             guint32               acd_timeout_msec,
                             NML3ConfigMergeFlags  merge_flags);

gboolean nm_l3cfg_remove_config(NML3Cfg *self, gconstpointer tag, const NML3ConfigData *ifcfg);

gboolean nm_l3cfg_remove_config_all(NML3Cfg *self, gconstpointer tag, gboolean only_dirty);

/*****************************************************************************/

/* The numeric values of the enum matters: higher number mean more "important".
 * E.g. "assume" tries to preserve the most settings, while "reapply" forces
 * all configuration to match. */
typedef enum _nm_packed {

    /* the NML3Cfg instance tracks with nm_l3cfg_commit_setup_register() the requested commit type.
     * Use _NM_L3_CFG_COMMIT_TYPE_AUTO to automatically choose the level as requested. */
    NM_L3_CFG_COMMIT_TYPE_AUTO,

    /* Don't touch the interface. */
    NM_L3_CFG_COMMIT_TYPE_NONE,

    /* ASSUME means to keep any pre-existing extra routes/addresses, while
     * also not adding routes/addresses that are not present yet. This is to
     * gracefully take over after restart, where the existing IP configuration
     * should not change. */
    NM_L3_CFG_COMMIT_TYPE_ASSUME,

    /* UPDATE means to add new addresses/routes, while also removing addresses/routes
     * that are no longer present (but were previously configured by NetworkManager).
     * Routes/addresses that were removed externally won't be re-added, and routes/addresses
     * that are added externally won't be removed. */
    NM_L3_CFG_COMMIT_TYPE_UPDATE,

    /* This is a full sync. It configures the IP addresses/routes that are indicated,
     * while removing the existing ones from the interface. */
    NM_L3_CFG_COMMIT_TYPE_REAPPLY,

} NML3CfgCommitType;

void nm_l3cfg_commit(NML3Cfg *self, NML3CfgCommitType commit_type);

void nm_l3cfg_commit_on_idle_schedule(NML3Cfg *self);

/*****************************************************************************/

const NML3AcdAddrInfo *nm_l3cfg_get_acd_addr_info(NML3Cfg *self, in_addr_t addr);

/*****************************************************************************/

NML3CfgCommitType nm_l3cfg_commit_type_get(NML3Cfg *self);

typedef struct _NML3CfgCommitTypeHandle NML3CfgCommitTypeHandle;

NML3CfgCommitTypeHandle *nm_l3cfg_commit_type_register(NML3Cfg *                self,
                                                       NML3CfgCommitType        commit_type,
                                                       NML3CfgCommitTypeHandle *existing_handle);

void nm_l3cfg_commit_type_unregister(NML3Cfg *self, NML3CfgCommitTypeHandle *handle);

/*****************************************************************************/

const NML3ConfigData *nm_l3cfg_get_combined_l3cd(NML3Cfg *self, gboolean get_commited);

const NMPObject *
nm_l3cfg_get_best_default_route(NML3Cfg *self, int addr_family, gboolean get_commited);

/*****************************************************************************/

gboolean nm_l3cfg_has_commited_ip6_addresses_pending_dad(NML3Cfg *self);

/*****************************************************************************/

struct _NML3IPv4LL *nm_l3cfg_get_ipv4ll(NML3Cfg *self);

struct _NML3IPv4LL *nm_l3cfg_access_ipv4ll(NML3Cfg *self);

void _nm_l3cfg_unregister_ipv4ll(NML3Cfg *self);

/*****************************************************************************/

#endif /* __NM_L3CFG_H__ */
